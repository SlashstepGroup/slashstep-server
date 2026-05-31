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
        role::{EditableRoleProperties, EditableRolePropertiesRequestBody, Role},
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_role_by_id, get_uuid_from_string, is_authenticated_user_anonymous,
        validate_field_length, verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /roles/{role_id} should be handled here.
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
pub mod memberships;

/// GET /roles/{role_id}
///
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_role_request(
    Path(role_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<Role>>, HTTPError> {
    let role_id =
        get_uuid_from_string(&role_id, "role", &http_transaction, &state.database_pool).await?;
    let target_role = get_role_by_id(&role_id, &http_transaction, &state.database_pool).await?;
    let get_roles_action =
        get_action_by_name("roles.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_roles_action.id,
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
        &ResourceType::Role,
        Some(&target_role.id),
        &get_roles_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_roles_action.id,
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
            target_role_id: Some(target_role.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned role {}.", target_role.id);

    let response_body = GetResourceResponseBody {
        data: target_role.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /roles/{role_id}
///
/// Deletes an role by its ID.
#[axum::debug_handler]
async fn handle_delete_role_request(
    Path(role_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let role_id =
        get_uuid_from_string(&role_id, "role", &http_transaction, &state.database_pool).await?;
    let target_role = get_role_by_id(&role_id, &http_transaction, &state.database_pool).await?;
    let delete_roles_action =
        get_action_by_name("roles.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_roles_action.id,
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
        &ResourceType::Role,
        Some(&target_role.id),
        &delete_roles_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if target_role.predefined_role_type.is_some() {
        let http_error = HTTPError::Forbidden(Some("Predefined roles should only be directly deleted by Slashstep Server. You can indirectly delete roles by deleting the parent resource.".to_string()));
        http_error.log();
        return Err(http_error);
    }

    if let Err(error) = target_role.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete role: {:?}", error)));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_roles_action.id,
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
            target_resource_type: ResourceType::Role,
            target_role_id: Some(target_role.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted role {}.", target_role.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /roles/{role_id}
///
/// Updates an role by its ID.
#[axum::debug_handler]
async fn handle_patch_role_request(
    Path(role_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableRolePropertiesRequestBody>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<Role>>, HTTPError> {
    let role_id =
        get_uuid_from_string(&role_id, "role", &http_transaction, &state.database_pool).await?;
    let updated_role_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(updated_role_display_name) = &updated_role_properties.display_name {
        validate_field_length(
            updated_role_display_name,
            "roles.maximumDisplayNameLength",
            "display_name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(Some(updated_role_description)) = &updated_role_properties.description {
        validate_field_length(
            updated_role_description,
            "roles.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    let original_target_role =
        get_role_by_id(&role_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("roles.update", &http_transaction, &state.database_pool).await?;
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
        &ResourceType::Role,
        Some(&original_target_role.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if original_target_role.predefined_role_type.is_some() {
        let http_error = HTTPError::Forbidden(Some("Predefined roles should only be updated by Slashstep Server. Use custom roles for more customization.".to_string()));
        http_error.log();
        return Err(http_error);
    }

    trace!("Updating role {}...", original_target_role.id);
    let updated_target_role = match original_target_role
        .update(
            &EditableRoleProperties {
                name: updated_role_properties.name.clone(),
                display_name: updated_role_properties.display_name.clone(),
                description: updated_role_properties.description.clone(),
            },
            &state.database_pool,
        )
        .await
    {
        Ok(updated_target_role) => updated_target_role,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update role {}: {:?}",
                original_target_role.id, error
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
            target_resource_type: ResourceType::Role,
            target_role_id: Some(updated_target_role.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated role {}.", updated_target_role.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_role,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/roles/{role_id}",
            axum::routing::get(handle_get_role_request),
        )
        .route(
            "/roles/{role_id}",
            axum::routing::delete(handle_delete_role_request),
        )
        .route(
            "/roles/{role_id}",
            axum::routing::patch(handle_patch_role_request),
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
        .merge(memberships::get_router(state.clone()))
}
