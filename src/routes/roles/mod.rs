/*
 *
 * Any functionality for /roles should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{role_id}/mod.rs"]
pub mod role_id;

use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{trace, info};

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
        role::{
            DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialRoleProperties, Role,
            RoleParentResourceType,
        },
        user::User,
    },
    routes::{ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        is_authenticated_user_anonymous, match_db_error, match_slashstepql_error,
        validate_field_length, validate_resource_name, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Query, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

/// GET /roles
///
/// Lists roles.
#[axum::debug_handler]
async fn handle_list_roles_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Role>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action =
        get_action_by_name("roles.list", &http_transaction, &state.database_pool).await?;
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

    trace!("Listing roles...");
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_resources = match Role::list(
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
                ResourceError::SlashstepQLError(error) => {
                    match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "roles")
                }

                ResourceError::PostgresError(error) => match_db_error(&error, "roles"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list roles: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting roles...");
    let resource_count = match Role::count(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(resource_count) => resource_count,

        Err(error) => {
            let http_error =
                HTTPError::InternalServerError(Some(format!("Failed to count roles: {:?}", error)));
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

    let queried_role_list_length = queried_resources.len();
    info!("Successfully returned {} {}.", queried_role_list_length, if queried_role_list_length == 1 { "role" } else { "roles" });

    let response_body = ListResourcesResponseBody::<Role> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateRoleRequestBody {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

/// POST /roles
///
/// Creates a role on the server level.
#[axum::debug_handler]
async fn handle_create_role_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<CreateRoleRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<Role>), HTTPError> {
    let create_role_request_body =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    validate_resource_name(
        &create_role_request_body.name,
        "roles.allowedNameRegex",
        "role",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_role_request_body.name,
        "roles.maximumNameLength",
        "name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_role_request_body.display_name,
        "roles.maximumDisplayNameLength",
        "display name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;

    if let Some(description) = &create_role_request_body.description {
        validate_field_length(
            description,
            "roles.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    // Make sure the authenticated_user can create apps for the target action log entry.
    let create_roles_action =
        get_action_by_name("roles.create", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_roles_action.id,
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
        &create_roles_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Create the role.
    trace!("Creating role...");
    let role = match Role::create(
        &InitialRoleProperties {
            name: create_role_request_body.name.clone(),
            display_name: create_role_request_body.display_name.clone(),
            description: create_role_request_body.description.clone(),
            parent_resource_type: RoleParentResourceType::Server,
            parent_group_id: None,
            parent_project_id: None,
            parent_workspace_id: None,
            parent_user_id: None,
            parent_app_id: None,
            predefined_role_type: None,
        },
        &state.database_pool,
    )
    .await
    {
        Ok(role) => role,

        Err(error) => {
            let http_error =
                HTTPError::InternalServerError(Some(format!("Failed to create role: {:?}", error)));
            http_error.log();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: create_roles_action.id,
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
            target_resource_type: ResourceType::Role,
            target_role_id: Some(role.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully created role {}.", role.id);

    Ok((StatusCode::CREATED, Json(role)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/roles", axum::routing::get(handle_list_roles_request))
        .route("/roles", axum::routing::post(handle_create_role_request))
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
        .merge(role_id::get_router(state.clone()))
}
