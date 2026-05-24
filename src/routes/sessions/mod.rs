/**
 *
 * Any functionality for /sessions should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{session_id}/mod.rs"]
mod session_id;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceError, ResourceType,
        access_policy::{AccessPolicyPrincipalType, PermissionLevel},
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialSessionProperties, Session},
        user::User,
    },
    routes::{CreateResourceResponseBody, ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_configuration_by_name,
        get_json_web_token_private_key, get_principal_type_and_id_from_principal,
        get_request_body_without_json_rejection, get_user_by_username,
        is_authenticated_user_anonymous, match_db_error, match_slashstepql_error,
        verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Query, State, rejection::JsonRejection},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use chrono::Utc;
use reqwest::StatusCode;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

/// POST /sessions
///
/// Creates a session for the authenticated user.
#[axum::debug_handler]
async fn handle_create_session_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    cookie_jar: CookieJar,
    body: Result<Json<LoginCredentials>, JsonRejection>,
) -> Result<
    (
        StatusCode,
        CookieJar,
        Json<CreateResourceResponseBody<Session>>,
    ),
    HTTPError,
> {
    // Make sure the requestor can create sessions on the target user.
    let login_credentials =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    let target_user = get_user_by_username(
        &login_credentials.username,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let create_sessions_action =
        get_action_by_name("sessions.create", &http_transaction, &state.database_pool).await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_sessions_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::User,
        Some(&target_user.id),
        &create_sessions_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Verify login credentials.
    if let Err(error) = target_user.verify_password(&login_credentials.password) {
        let http_error = match error {
            ResourceError::Argon2PasswordHashError(error) => match error {
                argon2::password_hash::Error::Password => Some(HTTPError::Unauthorized(Some(
                    "Invalid username or password. Check your credentials and try again."
                        .to_string(),
                ))),

                _ => None,
            },

            _ => None,
        }
        .unwrap_or(HTTPError::InternalServerError(Some(format!(
            "Failed to verify user password: {:?}",
            error
        ))));

        ServerLogEntry::from_http_error(
            &http_error,
            Some(&http_transaction.id),
            &state.database_pool,
        )
        .await
        .ok();
        return Err(http_error);
    }

    // Make sure the user can create sessions on themself.
    let (principal_type, principal_id) = (AccessPolicyPrincipalType::User, target_user.id.clone());
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        false,
        &ResourceType::User,
        Some(&target_user.id),
        &create_sessions_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Create the authenticated session.
    ServerLogEntry::trace(
        &format!("Creating session for user {}...", target_user.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let maximum_refresh_token_lifetime_milliseconds = match get_configuration_by_name(
        "sessions.maximumRefreshTokenLifetimeMilliseconds",
        &http_transaction,
        &state.database_pool,
    )
    .await
    {
        Ok(configuration) => {
            let number_value = configuration
                .number_value
                .or(configuration.default_number_value);
            if let Some(maximum_refresh_token_lifetime_milliseconds) = number_value
                && let Some(maximum_refresh_token_lifetime_milliseconds) =
                    maximum_refresh_token_lifetime_milliseconds.to_i64()
            {
                maximum_refresh_token_lifetime_milliseconds
            } else {
                let http_error = HTTPError::InternalServerError(Some("The sessions.maximumRefreshTokenLifetimeMilliseconds configuration must have a number value.".to_string()));
                ServerLogEntry::from_http_error(
                    &http_error,
                    Some(&http_transaction.id),
                    &state.database_pool,
                )
                .await
                .ok();
                return Err(http_error);
            }
        }

        Err(http_error) => return Err(http_error),
    };

    let created_session = match Session::create(
        &InitialSessionProperties {
            user_id: target_user.id,
            expiration_date: Utc::now()
                + chrono::Duration::milliseconds(maximum_refresh_token_lifetime_milliseconds),
            creation_ip_address: http_transaction.ip_address.clone(),
        },
        &state.database_pool,
    )
    .await
    {
        Ok(created_session) => created_session,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create session: {:?}",
                error
            )));
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    // Add the session token to the client's cookies.
    let jwt_private_key =
        get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?;
    let maximum_access_token_lifetime_milliseconds = match get_configuration_by_name(
        "sessions.maximumAccessTokenLifetimeMilliseconds",
        &http_transaction,
        &state.database_pool,
    )
    .await
    {
        Ok(configuration) => {
            let number_value = configuration
                .number_value
                .or(configuration.default_number_value);
            if let Some(maximum_access_token_lifetime_milliseconds) = number_value
                && let Some(maximum_access_token_lifetime_milliseconds) =
                    maximum_access_token_lifetime_milliseconds.to_i64()
            {
                maximum_access_token_lifetime_milliseconds
            } else {
                let http_error = HTTPError::InternalServerError(Some("The sessions.maximumAccessTokenLifetimeMilliseconds configuration must have a number value.".to_string()));
                ServerLogEntry::from_http_error(
                    &http_error,
                    Some(&http_transaction.id),
                    &state.database_pool,
                )
                .await
                .ok();
                return Err(http_error);
            }
        }

        Err(http_error) => return Err(http_error),
    };

    let access_token = if let Ok(token) = created_session
        .generate_access_token(
            &jwt_private_key,
            Utc::now() + chrono::Duration::milliseconds(maximum_access_token_lifetime_milliseconds),
        )
        .await
    {
        token
    } else {
        let http_error =
            HTTPError::InternalServerError(Some("Failed to generate session token.".to_string()));
        ServerLogEntry::from_http_error(
            &http_error,
            Some(&http_transaction.id),
            &state.database_pool,
        )
        .await
        .ok();
        return Err(http_error);
    };

    let refresh_token = if let Ok(token) = created_session
        .generate_refresh_token(&jwt_private_key)
        .await
    {
        token
    } else {
        let http_error =
            HTTPError::InternalServerError(Some("Failed to generate refresh token.".to_string()));
        ServerLogEntry::from_http_error(
            &http_error,
            Some(&http_transaction.id),
            &state.database_pool,
        )
        .await
        .ok();
        return Err(http_error);
    };

    let session_access_token_cookie = Cookie::build(("session_access_token", access_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::milliseconds(
            maximum_access_token_lifetime_milliseconds,
        ))
        .build();

    let session_refresh_token_cookie = Cookie::build(("session_refresh_token", refresh_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::milliseconds(
            maximum_refresh_token_lifetime_milliseconds,
        ))
        .build();

    let cookie_jar = cookie_jar
        .add(session_access_token_cookie)
        .add(session_refresh_token_cookie);

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: create_sessions_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: if let Some(authenticated_user) = &authenticated_user {
                Some(authenticated_user.id.clone())
            } else {
                None
            },
            actor_app_id: if let Some(authenticated_app) = &authenticated_app {
                Some(authenticated_app.id.clone())
            } else {
                None
            },
            target_resource_type: ResourceType::Session,
            target_session_id: Some(created_session.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!("Successfully created session {}.", created_session.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = CreateResourceResponseBody {
        data: created_session.clone(),
    };

    return Ok((StatusCode::CREATED, cookie_jar, Json(response_body)));
}

/// GET /sessions
///
/// Lists sessions.
#[axum::debug_handler]
async fn handle_list_sessions_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Session>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action =
        get_action_by_name("sessions.list", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &list_resources_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::Server,
        None,
        &list_resources_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    ServerLogEntry::trace(
        "Listing sessions...",
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_resources = match Session::list(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(queried_resources) => queried_resources,

        Err(error) => {
            let http_error = match error {
                ResourceError::SlashstepQLError(error) => match_slashstepql_error(
                    &error,
                    &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
                    "sessions",
                ),

                ResourceError::PostgresError(error) => match_db_error(&error, "sessions"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list sessions: {:?}",
                    error
                ))),
            };

            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    ServerLogEntry::trace(
        &format!("Counting sessions..."),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let resource_count = match Session::count(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(resource_count) => resource_count,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to count sessions: {:?}",
                error
            )));
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: list_resources_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp: expiration_timestamp,
            reason: None, // TODO: Support reasons.
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: if let Some(authenticated_user) = &authenticated_user {
                Some(authenticated_user.id.clone())
            } else {
                None
            },
            actor_app_id: if let Some(authenticated_app) = &authenticated_app {
                Some(authenticated_app.id.clone())
            } else {
                None
            },
            target_resource_type: ResourceType::Server,
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    let queried_session_list_length = queried_resources.len();
    ServerLogEntry::success(
        &format!(
            "Successfully returned {} {}.",
            queried_session_list_length,
            if queried_session_list_length == 1 {
                "session"
            } else {
                "sessions"
            }
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = ListResourcesResponseBody::<Session> {
        data: queried_resources,
        total_count: resource_count,
    };

    return Ok((StatusCode::OK, Json(response_body)));
}

pub fn get_router(state: AppState) -> Router<AppState> {
    let router = Router::<AppState>::new()
        .route(
            "/sessions",
            axum::routing::get(handle_list_sessions_request),
        )
        .route(
            "/sessions",
            axum::routing::post(handle_create_session_request),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware::verify_absolute_maximum_rate_limits,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_user,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_app,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http_transaction_middleware::create_http_transaction,
        ))
        .merge(session_id::get_router(state.clone()));
    return router;
}
