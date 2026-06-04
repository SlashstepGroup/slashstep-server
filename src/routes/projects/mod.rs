/*
 *
 * Any functionality for /projects should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{project_id}/mod.rs"]
pub mod project_id;

use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{info, trace};

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
        project::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, Project},
        user::User,
    },
    routes::{ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, is_authenticated_user_anonymous, match_db_error,
        match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Query, State},
};
use reqwest::StatusCode;

/// GET /projects
///
/// Lists projects.
#[axum::debug_handler]
async fn handle_list_projects_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Project>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action = get_action_by_name("projects.list", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &list_resources_action.id,
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
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Listing projects...");
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_resources = match Project::list(
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
                    "projects",
                ),

                ResourceError::PostgresError(error) => match_db_error(&error, "projects"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list projects: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting projects...");
    let resource_count = match Project::count(
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
                "Failed to count projects: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&state.database_pool).await?;
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

    let queried_project_list_length = queried_resources.len();
    info!(
        "Successfully returned {} {}.",
        queried_project_list_length,
        if queried_project_list_length == 1 {
            "project"
        } else {
            "projects"
        }
    );

    let response_body = ListResourcesResponseBody::<Project> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/projects",
            axum::routing::get(handle_list_projects_request),
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
        .merge(project_id::get_router(state.clone()))
}
