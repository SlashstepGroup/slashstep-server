use std::sync::Arc;

use axum::{
    Extension,
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use deadpool_redis::redis::AsyncCommands;
use rust_decimal::prelude::ToPrimitive;

use crate::{
    AppState, HTTPError,
    resources::{
        access_policy::AccessPolicyPrincipalType, app::App, app_authorization::AppAuthorization,
        user::User,
    },
    utilities::route_handler_utilities::{
        get_configuration_by_name, get_principal_type_and_id_from_principal,
    },
};

use tracing::info;

enum Interval {
    PerSecond,
    PerMinute,
}

impl std::fmt::Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interval::PerSecond => write!(f, "PerSecond"),
            Interval::PerMinute => write!(f, "PerMinute"),
        }
    }
}

#[axum_macros::debug_middleware]
pub async fn verify_absolute_maximum_rate_limits(
    State(state): State<AppState>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(_authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, HTTPError> {
    // Check per second rate limit.
    fn get_rate_limit_configuration_name(
        base_name: &str,
        interval: &Interval,
        principal_type: AccessPolicyPrincipalType,
        is_user_anonymous: bool,
    ) -> Result<String, HTTPError> {
        let per_principal_str = if principal_type == AccessPolicyPrincipalType::App {
            "PerApp"
        } else if is_user_anonymous {
            "PerAnonymousUser"
        } else {
            "PerRegisteredUser"
        };
        let rate_limit_configuration_name = format!("{base_name}{per_principal_str}{interval}");
        Ok(rate_limit_configuration_name)
    }

    let intervals = [Interval::PerSecond, Interval::PerMinute];

    for interval in intervals {
        let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
            authenticated_user.as_ref(),
            authenticated_app.as_ref(),
        )?;
        let is_user_anonymous = authenticated_user
            .as_ref()
            .map(|user| user.is_anonymous)
            .unwrap_or(false);
        let interval_rate_limit_configuration_name = match request.method() {
            &axum::http::Method::GET | &axum::http::Method::HEAD => {
                get_rate_limit_configuration_name(
                    "server.absoluteMaximumReadRequestCount",
                    &interval,
                    principal_type,
                    is_user_anonymous,
                )?
            }
            &axum::http::Method::POST
            | &axum::http::Method::PUT
            | &axum::http::Method::PATCH
            | &axum::http::Method::DELETE => get_rate_limit_configuration_name(
                "server.absoluteMaximumWriteRequestCount",
                &interval,
                principal_type,
                is_user_anonymous,
            )?,
            &axum::http::Method::OPTIONS => return Ok(next.run(request).await),
            _ => {
                let http_error = HTTPError::MethodNotAllowed(Some(format!(
                    "Requests with {} method are not allowed.",
                    request.method()
                )));
                http_error.log();
                return Err(http_error);
            }
        };

        let interval_rate_limit_configuration = get_configuration_by_name(
            &interval_rate_limit_configuration_name,
            &state.database_pool,
        )
        .await?;
        let interval_rate_limit = if let Some(interval_rate_limit_value) =
            interval_rate_limit_configuration
                .number_value
                .or(interval_rate_limit_configuration.default_number_value)
        {
            match interval_rate_limit_value.to_i64() {
                Some(interval_rate_limit) => interval_rate_limit,

                None => {
                    let http_error = HTTPError::InternalServerError(Some(format!(
                        "Invalid number value for configuration {}. The value must be a positive integer that can be represented as a usize.",
                        interval_rate_limit_configuration.id
                    )));
                    http_error.log();
                    return Err(http_error);
                }
            }
        } else {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Missing number value for configuration {}.",
                interval_rate_limit_configuration.id
            )));
            http_error.log();
            return Err(http_error);
        };

        let mut redis_connection = match state.redis_pool.get().await {
            Ok(connection) => connection,

            Err(error) => {
                let http_error = HTTPError::InternalServerError(Some(format!(
                    "Failed to get Redis connection from pool: {error:?}"
                )));
                http_error.log();
                return Err(http_error);
            }
        };
        let rate_limit_key = format!(
            "rateLimits.{interval_rate_limit_configuration_name}.{principal_type}.{principal_id}"
        );
        let rate_limit_current_request_count: i64 =
            match redis_connection.incr(&rate_limit_key, 1).await {
                Ok(count) => count,

                Err(error) => {
                    let http_error = HTTPError::InternalServerError(Some(format!(
                        "Failed to increment Redis key {rate_limit_key}: {:?}",
                        error
                    )));
                    http_error.log();
                    return Err(http_error);
                }
            };

        let expiration_seconds = match interval {
            Interval::PerSecond => 1,
            Interval::PerMinute => 60,
        };
        if rate_limit_current_request_count == 1
            && let Err(error) = redis_connection
                .expire::<_, ()>(&rate_limit_key, expiration_seconds)
                .await
        {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to set expiration for Redis key {rate_limit_key}: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }

        if rate_limit_current_request_count > interval_rate_limit {
            let http_error = HTTPError::TooManyRequests(Some(format!(
                "Rate limit exceeded for {}.",
                interval_rate_limit_configuration_name
            )));
            http_error.log();
            return Err(http_error);
        }
    }

    info!("Successfully verified principal is acting within global rate limits.");

    let response = next.run(request).await;
    Ok(response)
}
