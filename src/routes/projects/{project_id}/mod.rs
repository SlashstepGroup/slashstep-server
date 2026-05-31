use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        project::{EditableProjectProperties, Project},
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_project_by_id,
        get_request_body_without_json_rejection, get_uuid_from_string,
        is_authenticated_user_anonymous, validate_field_length, validate_resource_name,
        verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /projects/{project_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{trace, info};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;
pub mod fields;
#[path = "./item-connection-types/mod.rs"]
pub mod item_connection_types;
#[path = "./item-type-icons/mod.rs"]
pub mod item_type_icons;
#[path = "./item-types/mod.rs"]
pub mod item_types;
pub mod iterations;
pub mod milestones;
pub mod roles;
pub mod statuses;

pub mod views;

/// GET /projects/{project_id}
///
/// Gets a project by its ID.
#[axum::debug_handler]
async fn handle_get_project_request(
    Path(project_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<Project>>, HTTPError> {
    let project_id = get_uuid_from_string(
        &project_id,
        "project",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_project =
        get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
    let get_projects_action =
        get_action_by_name("projects.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_projects_action.id,
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
        &ResourceType::Project,
        Some(&target_project.id),
        &get_projects_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_projects_action.id,
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
            target_resource_type: ResourceType::Project,
            target_project_id: Some(target_project.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned project {}.", target_project.id);

    let response_body = GetResourceResponseBody {
        data: target_project.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /projects/{project_id}
///
/// Deletes an project by its ID.
#[axum::debug_handler]
async fn handle_delete_project_request(
    Path(project_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let project_id = get_uuid_from_string(
        &project_id,
        "project",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_project =
        get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
    let delete_projects_action =
        get_action_by_name("projects.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_projects_action.id,
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
        &ResourceType::Project,
        Some(&target_project.id),
        &delete_projects_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_project.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete project: {:?}", error)));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_projects_action.id,
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
            target_resource_type: ResourceType::Project,
            target_project_id: Some(target_project.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted project {}.", target_project.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /projects/{project_id}
///
/// Updates an project by its ID.
#[axum::debug_handler]
async fn handle_patch_project_request(
    Path(project_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableProjectProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<Project>>, HTTPError> {
    let project_id = get_uuid_from_string(
        &project_id,
        "project",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let updated_project_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(name) = &updated_project_properties.name {
        validate_field_length(
            name,
            "projects.maximumNameLength",
            "name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            name,
            "projects.allowedNameRegex",
            "project",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(display_name) = &updated_project_properties.display_name {
        validate_field_length(
            display_name,
            "projects.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(name) = &updated_project_properties.key {
        validate_field_length(
            name,
            "projects.maximumKeyLength",
            "key",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            name,
            "projects.allowedKeyRegex",
            "project",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(Some(description)) = &updated_project_properties.description {
        validate_field_length(
            description,
            "projects.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    let original_target_project =
        get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("projects.update", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &update_access_policy_action.id,
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
        &ResourceType::Project,
        Some(&original_target_project.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating project {}...", original_target_project.id);
    let updated_target_project = match original_target_project
        .update(&updated_project_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_project) => updated_target_project,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update project: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: update_access_policy_action.id,
            http_transaction_id: Some(http_transaction.id),
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
            target_resource_type: ResourceType::Project,
            target_project_id: Some(updated_target_project.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated project {}.", updated_target_project.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_project,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/projects/{project_id}",
            axum::routing::get(handle_get_project_request),
        )
        .route(
            "/projects/{project_id}",
            axum::routing::delete(handle_delete_project_request),
        )
        .route(
            "/projects/{project_id}",
            axum::routing::patch(handle_patch_project_request),
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
        .merge(access_policies::get_router(state.clone()))
        .merge(fields::get_router(state.clone()))
        .merge(milestones::get_router(state.clone()))
        .merge(item_connection_types::get_router(state.clone()))
        .merge(item_types::get_router(state.clone()))
        .merge(item_type_icons::get_router(state.clone()))
        .merge(iterations::get_router(state.clone()))
        .merge(roles::get_router(state.clone()))
        .merge(statuses::get_router(state.clone()))
        .merge(views::get_router(state.clone()))
}
