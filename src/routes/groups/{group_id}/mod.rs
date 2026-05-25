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
        group::{EditableGroupProperties, Group},
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_group_by_id,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length,
        validate_resource_name, verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /groups/{group_id} should be handled here.
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
#[path = "./membership-invitations/mod.rs"]
pub mod membership_invitations;
pub mod memberships;
pub mod roles;


/// GET /groups/{group_id}
///
/// Gets a group by its ID.
#[axum::debug_handler]
async fn handle_get_group_request(
    Path(group_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<Group>>, HTTPError> {
    let group_id =
        get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
    let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
    let get_groups_action =
        get_action_by_name("groups.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_groups_action.id,
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
        &ResourceType::Group,
        Some(&target_group.id),
        &get_groups_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_groups_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::Group,
            target_group_id: Some(target_group.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!("Successfully returned group {}.", target_group.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = GetResourceResponseBody {
        data: target_group.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /groups/{group_id}
///
/// Deletes a group by its ID.
#[axum::debug_handler]
async fn handle_delete_group_request(
    Path(group_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let group_id =
        get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
    let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
    let delete_groups_action =
        get_action_by_name("groups.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_groups_action.id,
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
        &ResourceType::Group,
        Some(&target_group.id),
        &delete_groups_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_group.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete group: {:?}", error)));
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
            action_id: delete_groups_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            reason: None, // TODO: Support reasons.
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::Group,
            target_group_id: Some(target_group.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    ServerLogEntry::success(
        &format!("Successfully deleted group {}.", target_group.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /groups/{group_id}
///
/// Updates a group by its ID.
#[axum::debug_handler]
async fn handle_patch_group_request(
    Path(group_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableGroupProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<Group>>, HTTPError> {
    let group_id =
        get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
    let updated_group_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(updated_group_name) = &updated_group_properties.name {
        validate_resource_name(
            updated_group_name,
            "groups.allowedNameRegex",
            "group",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_field_length(
            updated_group_name,
            "groups.maximumNameLength",
            "name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(updated_group_display_name) = &updated_group_properties.display_name {
        validate_field_length(
            updated_group_display_name,
            "groups.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(Some(updated_group_description)) = &updated_group_properties.description {
        validate_field_length(
            updated_group_description,
            "groups.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    let original_target_group =
        get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("groups.update", &http_transaction, &state.database_pool).await?;
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
        &ResourceType::Group,
        Some(&original_target_group.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    ServerLogEntry::trace(
        &format!("Updating group {}...", original_target_group.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let updated_target_group = match original_target_group
        .update(&updated_group_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_group) => updated_target_group,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update group {}: {:?}",
                original_target_group.id, error
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
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::Group,
            target_group_id: Some(updated_target_group.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!("Successfully updated group {}.", updated_target_group.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = PatchResourceResponseBody {
        data: updated_target_group,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    
    Router::<AppState>::new()
        .route(
            "/groups/{group_id}",
            axum::routing::get(handle_get_group_request),
        )
        .route(
            "/groups/{group_id}",
            axum::routing::delete(handle_delete_group_request),
        )
        .route(
            "/groups/{group_id}",
            axum::routing::patch(handle_patch_group_request),
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
        .merge(membership_invitations::get_router(state.clone()))
        .merge(memberships::get_router(state.clone()))
        .merge(roles::get_router(state.clone()))
}
