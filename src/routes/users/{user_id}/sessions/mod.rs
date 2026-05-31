/*
 *
 * Any functionality for /users/{user_id}/sessions should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use crate::utilities::route_handler_utilities::create_trace_layer_span;
use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceError, ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, Session},
        user::User,
    },
    routes::{ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_user_by_id, get_uuid_from_string,
        is_authenticated_user_anonymous, match_db_error, match_slashstepql_error,
        verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::trace;

/// GET /users/{user_id}/sessions
///
/// Lists sessions for an app.
#[axum::debug_handler]
pub async fn handle_list_sessions_request(
    Path(user_id): Path<String>,
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Session>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let user_id =
        get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
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
    let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::User,
        Some(&target_user.id),
        &list_resources_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let query = format!(
        "user_id = {}{}",
        quote_literal(&user_id.to_string()),
        query_parameters
            .query
            .map(|query| format!(" AND ({})", query))
            .unwrap_or("".to_string())
    );
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

    trace!("Counting sessions...");
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
            target_resource_type: ResourceType::User,
            target_user_id: Some(target_user.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    let queried_resource_list_length = queried_resources.len();
    ServerLogEntry::success(
        &format!(
            "Successfully returned {} {}.",
            queried_resource_list_length,
            if queried_resource_list_length == 1 {
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

    Ok((StatusCode::OK, Json(response_body)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/users/{user_id}/sessions",
            axum::routing::get(handle_list_sessions_request),
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
}
