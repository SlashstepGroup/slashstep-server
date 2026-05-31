/*
 *
 * Any functionality for /session-credentials should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{session_credential_id}/mod.rs"]
pub mod session_credential_id;

use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{info, trace};

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
        session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialSessionProperties, Session},
        session_credential::{InitialSessionCredentialProperties, SessionCredential},
        user::User,
    },
    routes::{CreateResourceResponseBody, ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_configuration_by_name,
        get_json_web_token_private_key, get_principal_type_and_id_from_principal,
        get_request_body_without_json_rejection, get_user_by_id, get_user_by_username,
        get_uuid_from_string, is_authenticated_user_anonymous, match_db_error,
        match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions,
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
pub enum AuthenticationMethod {
    LoginCredentials,
    RefreshToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationCredentials {
    pub authentication_method: AuthenticationMethod,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// POST /session-credentials
///
/// Creates a session credential for the authenticated user.
#[axum::debug_handler]
async fn handle_create_session_credential_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    cookie_jar: CookieJar,
    body: Result<Json<AuthenticationCredentials>, JsonRejection>,
) -> Result<
    (
        StatusCode,
        CookieJar,
        Json<CreateResourceResponseBody<SessionCredential>>,
    ),
    HTTPError,
> {
    async fn get_invalid_refresh_token_http_error(
        http_transaction: &HTTPTransaction,
        database_pool: &deadpool_postgres::Pool,
    ) -> HTTPError {
        let http_error = HTTPError::Unauthorized(Some(
            "Invalid refresh token. Check your credentials and try again.".to_string(),
        ));
        http_error.log();
        http_error
    }

    async fn get_invalid_login_credentials_http_error(
        http_transaction: &HTTPTransaction,
        database_pool: &deadpool_postgres::Pool,
    ) -> HTTPError {
        let http_error = HTTPError::Unauthorized(Some(
            "Invalid username or password. Check your credentials and try again.".to_string(),
        ));
        http_error.log();
        http_error
    }

    async fn get_user_from_authentication_credentials(
        authentication_credentials: &Json<AuthenticationCredentials>,
        http_transaction: &HTTPTransaction,
        database_pool: &deadpool_postgres::Pool,
        cookie_jar: &CookieJar,
    ) -> Result<User, HTTPError> {
        match authentication_credentials.authentication_method {
            AuthenticationMethod::LoginCredentials => {
                let Some(username) = &authentication_credentials.username else {
                    let http_error = HTTPError::BadRequest(Some(
                        "The username field is required when using login credentials.".to_string(),
                    ));
                    http_error.log();
                    return Err(http_error);
                };

                Ok(get_user_by_username(&username, &http_transaction, &database_pool).await?)
            }

            AuthenticationMethod::RefreshToken => {
                let Some(session_refresh_token) = cookie_jar
                    .get("session_refresh_token")
                    .map(|cookie| cookie.value())
                else {
                    let http_error = HTTPError::BadRequest(Some(
                        "The refresh_token field is required when using a refresh token."
                            .to_string(),
                    ));
                    http_error.log();
                    return Err(http_error);
                };

                let decoded_claims = match SessionCredential::decode_token(
                    &session_refresh_token,
                    &get_json_web_token_private_key(&http_transaction.id, &database_pool).await?,
                ) {
                    Ok(decoded_claims) => decoded_claims,

                    Err(_) => {
                        return Err(get_invalid_refresh_token_http_error(
                            http_transaction,
                            database_pool,
                        )
                        .await);
                    }
                };
                let user_id_string = decoded_claims.sub;
                let user_id = get_uuid_from_string(
                    &user_id_string,
                    "user",
                    &http_transaction,
                    &database_pool,
                )
                .await?;
                Ok(get_user_by_id(&user_id, &http_transaction, &database_pool).await?)
            }
        }
    }

    // Make sure the requestor can create sessions on the target user.
    let authentication_credentials =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;

    let target_user = get_user_from_authentication_credentials(
        &authentication_credentials,
        &http_transaction,
        &state.database_pool,
        &cookie_jar,
    )
    .await?;
    let create_session_credentials_action = get_action_by_name(
        "sessionCredentials.create",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_session_credentials_action.id,
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
        &create_session_credentials_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Verify login credentials.
    match authentication_credentials.authentication_method {
        AuthenticationMethod::LoginCredentials => {
            let Some(provided_password) = &authentication_credentials.password else {
                let http_error = HTTPError::BadRequest(Some(
                    "The password field is required when using login credentials.".to_string(),
                ));
                http_error.log();
                return Err(http_error);
            };

            if let Err(error) = target_user.verify_password(&provided_password) {
                let http_error = match error {
                    ResourceError::Argon2PasswordHashError(error) => match error {
                        argon2::password_hash::Error::Password => {
                            return Err(get_invalid_login_credentials_http_error(
                                &http_transaction,
                                &state.database_pool,
                            )
                            .await);
                        }

                        _ => None,
                    },

                    _ => None,
                }
                .unwrap_or(HTTPError::InternalServerError(Some(format!(
                    "Failed to verify user password: {:?}",
                    error
                ))));

                http_error.log();
                return Err(http_error);
            }
        }

        AuthenticationMethod::RefreshToken => {
            let Some(session_refresh_token) = &cookie_jar
                .get("session_refresh_token")
                .map(|cookie| cookie.value())
            else {
                let http_error = HTTPError::BadRequest(Some(
                    "The refresh_token field is required when using a refresh token.".to_string(),
                ));
                http_error.log();
                return Err(http_error);
            };
            let decoded_claims = match SessionCredential::decode_token(
                &session_refresh_token,
                &get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?,
            ) {
                Ok(decoded_claims) => decoded_claims,

                Err(_) => {
                    return Err(get_invalid_refresh_token_http_error(
                        &http_transaction,
                        &state.database_pool,
                    )
                    .await);
                }
            };
            let session_credential_id_string = decoded_claims.jti;
            let session_credential_id = get_uuid_from_string(
                &session_credential_id_string,
                "session credential",
                &http_transaction,
                &state.database_pool,
            )
            .await?;
            let session_credential =
                match SessionCredential::get_by_id(&session_credential_id, &state.database_pool)
                    .await
                {
                    Ok(session_credential) => session_credential,
                    Err(error) => {
                        let http_error = match error {
                            ResourceError::NotFoundError(_) => HTTPError::Unauthorized(Some(
                                "Invalid refresh token. Check your credentials and try again."
                                    .to_string(),
                            )),

                            _ => HTTPError::InternalServerError(Some(format!(
                                "Failed to get session credential by ID: {:?}",
                                error
                            ))),
                        };

                        http_error.log();
                        return Err(http_error);
                    }
                };
            let session = match Session::get_by_id(
                &session_credential.session_id,
                &state.database_pool,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    let http_error = match error {
                        ResourceError::NotFoundError(_) => HTTPError::Unauthorized(Some(
                            "Invalid refresh token. Check your credentials and try again."
                                .to_string(),
                        )),

                        _ => HTTPError::InternalServerError(Some(format!(
                            "Failed to get session by ID: {:?}",
                            error
                        ))),
                    };

                    http_error.log();
                    return Err(http_error);
                }
            };
            if session_credential.refreshed_session_credential_id.is_some()
                || !session_credential.is_access_token_expired()
            {
                session.delete(&state.database_pool).await.ok();

                let http_error = HTTPError::Unauthorized(Some(
                    "To protect this account's security, the session associated with this refresh token has expired. Please authenticate using login credentials to make a new session.".to_string(),
                ));
                http_error.log();
                return Err(http_error);
            }
            if session.is_expired() {
                let http_error = HTTPError::Unauthorized(Some(
                    "The session associated with this refresh token has expired. Authenticate again to get a new refresh token.".to_string(),
                ));
                http_error.log();
                return Err(http_error);
            }
        }
    }

    // Make sure the user can create sessions on themself.
    let (principal_type, principal_id) = (AccessPolicyPrincipalType::User, target_user.id);
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        false,
        &ResourceType::User,
        Some(&target_user.id),
        &create_session_credentials_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Create the authenticated session.
    trace!("Creating session for user {}...", target_user.id);

    let maximum_session_lifetime_milliseconds = match get_configuration_by_name(
        "sessions.maximumLifetimeMilliseconds",
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
                http_error.log();
                return Err(http_error);
            }
        }

        Err(http_error) => return Err(http_error),
    };

    let created_session = match Session::create(
        &InitialSessionProperties {
            user_id: target_user.id,
            expiration_date: Utc::now()
                + chrono::Duration::milliseconds(maximum_session_lifetime_milliseconds),
            creation_ip_address: http_transaction.ip_address,
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
            http_error.log();
            return Err(http_error);
        }
    };

    let maximum_access_token_lifetime_milliseconds = match get_configuration_by_name(
        "sessionCredentials.maximumAccessTokenLifetimeMilliseconds",
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
                let http_error = HTTPError::InternalServerError(Some("The sessionCredentials.maximumAccessTokenLifetimeMilliseconds configuration must have a number value.".to_string()));
                http_error.log();
                return Err(http_error);
            }
        }

        Err(http_error) => return Err(http_error),
    };

    let maximum_refresh_token_lifetime_milliseconds = match get_configuration_by_name(
        "sessionCredentials.maximumRefreshTokenLifetimeMilliseconds",
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
                let http_error = HTTPError::InternalServerError(Some("The sessionCredentials.maximumRefreshTokenLifetimeMilliseconds configuration must have a number value.".to_string()));
                http_error.log();
                return Err(http_error);
            }
        }

        Err(http_error) => return Err(http_error),
    };

    let created_session_credential = match SessionCredential::create(
        &InitialSessionCredentialProperties {
            user_id: created_session.user_id,
            session_id: created_session.id,
            creation_ip_address: created_session.creation_ip_address,
            access_token_expiration_date: Utc::now()
                + chrono::Duration::milliseconds(maximum_access_token_lifetime_milliseconds),
            refresh_token_expiration_date: Utc::now()
                + chrono::Duration::milliseconds(maximum_refresh_token_lifetime_milliseconds),
            refreshed_session_credential_id: None,
        },
        &state.database_pool,
    )
    .await
    {
        Ok(created_session_credential) => created_session_credential,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create session credential: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    // Add the session token to the client's cookies.
    let jwt_private_key =
        get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?;

    let access_token = if let Ok(token) = created_session_credential
        .generate_access_token(&jwt_private_key)
        .await
    {
        token
    } else {
        let http_error =
            HTTPError::InternalServerError(Some("Failed to generate session token.".to_string()));
        http_error.log();
        return Err(http_error);
    };

    let refresh_token = if let Ok(token) = created_session_credential
        .generate_refresh_token(&jwt_private_key)
        .await
    {
        token
    } else {
        let http_error =
            HTTPError::InternalServerError(Some("Failed to generate refresh token.".to_string()));
        http_error.log();
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
            action_id: create_session_credentials_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::SessionCredential,
            target_session_id: Some(created_session.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully created session {}.", created_session.id);

    let response_body = CreateResourceResponseBody {
        data: created_session_credential.clone(),
    };

    Ok((StatusCode::CREATED, cookie_jar, Json(response_body)))
}

/// GET /session-credentials
///
/// Lists sessionCredentials.
#[axum::debug_handler]
async fn handle_list_session_credentials_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Session>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action = get_action_by_name(
        "sessionCredentials.list",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
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

    trace!("Listing sessionCredentials...");
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

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting sessionCredentials...");
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
            http_error.log();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: list_resources_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            reason: None, // TODO: Support reasons.
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::Server,
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    let queried_session_credential_list_length = queried_resources.len();
    info!(
        "Successfully returned {} {}.",
        queried_session_credential_list_length,
        if queried_session_credential_list_length == 1 {
            "session"
        } else {
            "sessions"
        }
    );

    let response_body = ListResourcesResponseBody::<Session> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/session-credentials",
            axum::routing::get(handle_list_session_credentials_request),
        )
        .route(
            "/session-credentials",
            axum::routing::post(handle_create_session_credential_request),
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
        .layer(TraceLayer::new_for_http().make_span_with(create_trace_layer_span))
        .merge(session_credential_id::get_router(state.clone()))
}
