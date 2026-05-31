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
        item_type::{EditableItemTypeProperties, ItemType},
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_item_type_by_id,
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
 * Any functionality for /item-types/{item_type_id} should be handled here.
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
use tracing::{info, trace};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

/// GET /item-types/{item_type_id}
///
/// Gets a item type by its ID.
#[axum::debug_handler]
async fn handle_get_item_type_request(
    Path(item_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<ItemType>>, HTTPError> {
    let item_type_id = get_uuid_from_string(&item_type_id, "item type").await?;
    let target_item_type = get_item_type_by_id(&item_type_id, &state.database_pool).await?;
    let get_item_types_action = get_action_by_name("itemTypes.get", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_item_types_action.id,
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
        &ResourceType::ItemType,
        Some(&target_item_type.id),
        &get_item_types_action,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_item_types_action.id,
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
            target_resource_type: ResourceType::ItemType,
            target_item_type_id: Some(target_item_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned item type {}.", target_item_type.id);

    let response_body = GetResourceResponseBody {
        data: target_item_type.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /item-types/{item_type_id}
///
/// Deletes an item type by its ID.
#[axum::debug_handler]
async fn handle_delete_item_type_request(
    Path(item_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let item_type_id = get_uuid_from_string(&item_type_id, "item type").await?;
    let target_item_type = get_item_type_by_id(&item_type_id, &state.database_pool).await?;
    let delete_item_types_action =
        get_action_by_name("itemTypes.delete", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_item_types_action.id,
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
        &ResourceType::ItemType,
        Some(&target_item_type.id),
        &delete_item_types_action,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_item_type.delete(&state.database_pool).await {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete item type: {:?}",
            error
        )));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_item_types_action.id,
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
            target_resource_type: ResourceType::ItemType,
            target_item_type_id: Some(target_item_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted item type {}.", target_item_type.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /item-types/{item_type_id}
///
/// Updates an item type by its ID.
#[axum::debug_handler]
async fn handle_patch_item_type_request(
    Path(item_type_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableItemTypeProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<ItemType>>, HTTPError> {
    let item_type_id = get_uuid_from_string(&item_type_id, "item type").await?;
    let updated_item_type_properties = get_request_body_without_json_rejection(body).await?;
    if let Some(name) = &updated_item_type_properties.name {
        validate_field_length(
            name,
            "itemTypes.maximumNameLength",
            "name",
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            name,
            "itemTypes.allowedNameRegex",
            "item type",
            &state.database_pool,
        )
        .await?;
    }

    if let Some(display_name) = &updated_item_type_properties.display_name {
        validate_field_length(
            display_name,
            "itemTypes.maximumDisplayNameLength",
            "display name",
            &state.database_pool,
        )
        .await?;
    }

    if let Some(Some(description)) = &updated_item_type_properties.description {
        validate_field_length(
            description,
            "itemTypes.maximumDescriptionLength",
            "description",
            &state.database_pool,
        )
        .await?;
    }

    let original_target_item_type =
        get_item_type_by_id(&item_type_id, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("itemTypes.update", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &update_access_policy_action.id,
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
        &ResourceType::ItemType,
        Some(&original_target_item_type.id),
        &update_access_policy_action,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating item type {}...", original_target_item_type.id);
    let updated_target_item_type = match original_target_item_type
        .update(&updated_item_type_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_item_type) => updated_target_item_type,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update item type: {:?}",
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
            target_resource_type: ResourceType::ItemType,
            target_item_type_id: Some(updated_target_item_type.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!(
        "Successfully updated item type {}.",
        updated_target_item_type.id
    );

    let response_body = PatchResourceResponseBody {
        data: updated_target_item_type,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/item-types/{item_type_id}",
            axum::routing::get(handle_get_item_type_request),
        )
        .route(
            "/item-types/{item_type_id}",
            axum::routing::delete(handle_delete_item_type_request),
        )
        .route(
            "/item-types/{item_type_id}",
            axum::routing::patch(handle_patch_item_type_request),
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
}
