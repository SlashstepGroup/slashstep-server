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
        server_log_entry::ServerLogEntry,
        user::User,
        workspace::{
            EditableWorkspaceProperties, EditableWorkspacePropertiesRequestBody, Workspace,
        },
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, get_workspace_by_id, is_authenticated_user_anonymous,
        validate_field_length, validate_resource_name, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /workspaces/{workspace_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use std::sync::Arc;

#[path = "./access-policies/mod.rs"]
pub mod access_policies;
pub mod apps;
pub mod projects;
pub mod roles;

/// GET /workspaces/{workspace_id}
///
/// Gets a workspace by its ID.
#[axum::debug_handler]
async fn handle_get_workspace_request(
    Path(workspace_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<Workspace>>, HTTPError> {
    let workspace_id = get_uuid_from_string(
        &workspace_id,
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_workspace =
        get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
    let get_workspaces_action =
        get_action_by_name("workspaces.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_workspaces_action.id,
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
        &ResourceType::Workspace,
        Some(&target_workspace.id),
        &get_workspaces_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_workspaces_action.id,
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
            target_resource_type: ResourceType::Workspace,
            target_workspace_id: Some(target_workspace.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!("Successfully returned workspace {}.", target_workspace.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = GetResourceResponseBody {
        data: target_workspace.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /workspaces/{workspace_id}
///
/// Deletes an workspace by its ID.
#[axum::debug_handler]
async fn handle_delete_workspace_request(
    Path(workspace_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let workspace_id = get_uuid_from_string(
        &workspace_id,
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_workspace =
        get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
    let delete_workspaces_action =
        get_action_by_name("workspaces.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_workspaces_action.id,
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
        &ResourceType::Workspace,
        Some(&target_workspace.id),
        &delete_workspaces_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_workspace.delete(&state.database_pool).await {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete workspace: {:?}",
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

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_workspaces_action.id,
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
            target_resource_type: ResourceType::Workspace,
            target_workspace_id: Some(target_workspace.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    ServerLogEntry::success(
        &format!("Successfully deleted workspace {}.", target_workspace.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /workspaces/{workspace_id}
///
/// Updates an workspace by its ID.
#[axum::debug_handler]
async fn handle_patch_workspace_request(
    Path(workspace_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableWorkspacePropertiesRequestBody>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<Workspace>>, HTTPError> {
    let workspace_id = get_uuid_from_string(
        &workspace_id,
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let updated_workspace_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(name) = &updated_workspace_properties.name {
        validate_field_length(
            name,
            "workspaces.maximumNameLength",
            "name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            name,
            "workspaces.allowedNameRegex",
            "workspace",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(display_name) = &updated_workspace_properties.display_name {
        validate_field_length(
            display_name,
            "workspaces.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(Some(description)) = &updated_workspace_properties.description {
        validate_field_length(
            description,
            "workspaces.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    let original_target_workspace =
        get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("workspaces.update", &http_transaction, &state.database_pool).await?;
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
        &ResourceType::Workspace,
        Some(&original_target_workspace.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    ServerLogEntry::trace(
        &format!("Updating workspace {}...", original_target_workspace.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let updated_target_workspace = match original_target_workspace
        .update(
            &EditableWorkspaceProperties {
                name: updated_workspace_properties.name.clone(),
                display_name: updated_workspace_properties.display_name.clone(),
                description: updated_workspace_properties.description.clone(),
            },
            &state.database_pool,
        )
        .await
    {
        Ok(updated_target_workspace) => updated_target_workspace,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update workspace: {:?}",
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
            target_resource_type: ResourceType::Workspace,
            target_workspace_id: Some(updated_target_workspace.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!(
            "Successfully updated workspace {}.",
            updated_target_workspace.id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = PatchResourceResponseBody {
        data: updated_target_workspace,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/workspaces/{workspace_id}",
            axum::routing::get(handle_get_workspace_request),
        )
        .route(
            "/workspaces/{workspace_id}",
            axum::routing::delete(handle_delete_workspace_request),
        )
        .route(
            "/workspaces/{workspace_id}",
            axum::routing::patch(handle_patch_workspace_request),
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
        .merge(access_policies::get_router(state.clone()))
        .merge(apps::get_router(state.clone()))
        .merge(projects::get_router(state.clone()))
        .merge(roles::get_router(state.clone()))
}
