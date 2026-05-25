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
        item_connection_type::{EditableItemConnectionTypeProperties, ItemConnectionType},
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_item_connection_type_by_id, get_principal_type_and_id_from_principal,
        get_request_body_without_json_rejection, get_uuid_from_string,
        is_authenticated_user_anonymous, validate_field_length, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/**
 *
 * Any functionality for /item-connection-types/{item_connection_type_id} should be handled here.
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


/// GET /item-connection-types/{item_connection_type_id}
///
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_item_connection_type_request(
    Path(item_connection_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<ItemConnectionType>>, HTTPError> {
    let item_connection_type_id = get_uuid_from_string(
        &item_connection_type_id,
        "item connection type",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_item_connection_type = get_item_connection_type_by_id(
        &item_connection_type_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let get_item_connection_types_action = get_action_by_name(
        "itemConnectionTypes.get",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_item_connection_types_action.id,
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
        &ResourceType::ItemConnectionType,
        Some(&target_item_connection_type.id),
        &get_item_connection_types_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_item_connection_types_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::ItemConnectionType,
            target_item_connection_type_id: Some(target_item_connection_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!(
            "Successfully returned item connection type {}.",
            target_item_connection_type.id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = GetResourceResponseBody {
        data: target_item_connection_type.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /item-connection-types/{item_connection_type_id}
///
/// Deletes an item connection type by its ID.
#[axum::debug_handler]
async fn handle_delete_item_connection_type_request(
    Path(item_connection_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let item_connection_type_id = get_uuid_from_string(
        &item_connection_type_id,
        "item connection type",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_item_connection_type = get_item_connection_type_by_id(
        &item_connection_type_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let delete_item_connection_types_action = get_action_by_name(
        "itemConnectionTypes.delete",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_item_connection_types_action.id,
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
        &ResourceType::ItemConnectionType,
        Some(&target_item_connection_type.id),
        &delete_item_connection_types_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_item_connection_type
        .delete(&state.database_pool)
        .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete item connection type: {:?}",
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
            action_id: delete_item_connection_types_action.id,
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
            target_resource_type: ResourceType::ItemConnectionType,
            target_item_connection_type_id: Some(target_item_connection_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    ServerLogEntry::success(
        &format!(
            "Successfully deleted item connection type {}.",
            target_item_connection_type.id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /item-connection-types/{item_connection_type_id}
///
/// Updates an item connection type by its ID.
#[axum::debug_handler]
async fn handle_patch_item_connection_type_request(
    Path(item_connection_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableItemConnectionTypeProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<ItemConnectionType>>, HTTPError> {
    let item_connection_type_id = get_uuid_from_string(
        &item_connection_type_id,
        "item connection type",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let updated_item_connection_type_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(updated_item_connection_type_display_name) =
        &updated_item_connection_type_properties.display_name
    {
        validate_field_length(
            updated_item_connection_type_display_name,
            "itemConnectionTypes.maximumDisplayNameLength",
            "display_name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(updated_item_connection_type_inward_description) =
        &updated_item_connection_type_properties.inward_description
    {
        validate_field_length(
            updated_item_connection_type_inward_description,
            "itemConnectionTypes.maximumDescriptionLength",
            "inward_description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(updated_item_connection_type_outward_description) =
        &updated_item_connection_type_properties.outward_description
    {
        validate_field_length(
            updated_item_connection_type_outward_description,
            "itemConnectionTypes.maximumDescriptionLength",
            "outward_description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    let original_target_item_connection_type = get_item_connection_type_by_id(
        &item_connection_type_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let update_access_policy_action = get_action_by_name(
        "itemConnectionTypes.update",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
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
        &ResourceType::ItemConnectionType,
        Some(&original_target_item_connection_type.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    ServerLogEntry::trace(
        &format!(
            "Updating item connection type {}...",
            original_target_item_connection_type.id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let updated_target_item_connection_type = match original_target_item_connection_type
        .update(
            &updated_item_connection_type_properties,
            &state.database_pool,
        )
        .await
    {
        Ok(updated_target_item_connection_type) => updated_target_item_connection_type,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update item connection type {}: {:?}",
                original_target_item_connection_type.id, error
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
            target_resource_type: ResourceType::ItemConnectionType,
            target_item_connection_type_id: Some(updated_target_item_connection_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    ServerLogEntry::success(
        &format!(
            "Successfully updated item connection type {}.",
            updated_target_item_connection_type.id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = PatchResourceResponseBody {
        data: updated_target_item_connection_type,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    
    Router::<AppState>::new()
        .route(
            "/item-connection-types/{item_connection_type_id}",
            axum::routing::get(handle_get_item_connection_type_request),
        )
        .route(
            "/item-connection-types/{item_connection_type_id}",
            axum::routing::delete(handle_delete_item_connection_type_request),
        )
        .route(
            "/item-connection-types/{item_connection_type_id}",
            axum::routing::patch(handle_patch_item_connection_type_request),
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
}
