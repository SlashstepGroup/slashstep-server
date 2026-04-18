/**
 * 
 * Any functionality for /item-type-icons/{item_type_icon_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_transaction_middleware}, 
  resources::{
    ResourceType, access_policy::ActionPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, item_type_icon::{EditableItemTypeIconProperties, ItemTypeIcon}, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_item_type_icon_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length, verify_delegate_permissions, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /item-type-icons/{item_type_icon_id}
/// 
/// Gets a item type icon by its ID.
#[axum::debug_handler]
async fn handle_get_item_type_icon_request(
  Path(item_type_icon_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<ItemTypeIcon>, HTTPError> {

  let item_type_icon_id = get_uuid_from_string(&item_type_icon_id, "item type icon", &http_transaction, &state.database_pool).await?;
  let target_item_type_icon = get_item_type_icon_by_id(&item_type_icon_id, &http_transaction, &state.database_pool).await?;
  let get_item_type_icons_action = get_action_by_name("itemTypeIcons.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_item_type_icons_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemTypeIcon, Some(&target_item_type_icon.id), &get_item_type_icons_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_item_type_icons_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::ItemTypeIcon,
    target_item_type_icon_id: Some(target_item_type_icon.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned item type icon {}.", target_item_type_icon.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_item_type_icon));

}

/// DELETE /item-type-icons/{item_type_icon_id}
/// 
/// Deletes an item type icon by its ID.
#[axum::debug_handler]
async fn handle_delete_item_type_icon_request(
  Path(item_type_icon_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let item_type_icon_id = get_uuid_from_string(&item_type_icon_id, "item type icon", &http_transaction, &state.database_pool).await?;
  let target_item_type_icon = get_item_type_icon_by_id(&item_type_icon_id, &http_transaction, &state.database_pool).await?;
  let delete_item_type_icons_action = get_action_by_name("itemTypeIcons.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_item_type_icons_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemTypeIcon, Some(&target_item_type_icon.id), &delete_item_type_icons_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  if let Err(error) = target_item_type_icon.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete item type icon: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_item_type_icons_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::ItemTypeIcon,
    target_item_type_icon_id: Some(target_item_type_icon.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted item type icon {}.", target_item_type_icon.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /item-type-icons/{item_type_icon_id}
/// 
/// Updates an item type icon by its ID.
#[axum::debug_handler]
async fn handle_patch_item_type_icon_request(
  Path(item_type_icon_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableItemTypeIconProperties>, JsonRejection>
) -> Result<Json<ItemTypeIcon>, HTTPError> {

  let item_type_icon_id = get_uuid_from_string(&item_type_icon_id, "item type icon", &http_transaction, &state.database_pool).await?;
  let updated_item_type_icon_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  if let Some(display_name) = &updated_item_type_icon_properties.display_name {

    validate_field_length(display_name, "itemTypeIcons.maximumDisplayNameLength", "display name", &http_transaction, &state.database_pool).await?;

  }
  
  let original_target_item_type_icon = get_item_type_icon_by_id(&item_type_icon_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("itemTypeIcons.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemTypeIcon, Some(&original_target_item_type_icon.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating item type icon {}...", original_target_item_type_icon.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_item_type_icon = match original_target_item_type_icon.update(&updated_item_type_icon_properties, &state.database_pool).await {

    Ok(updated_target_item_type_icon) => updated_target_item_type_icon,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update item type icon: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::ItemTypeIcon,
    target_item_type_icon_id: Some(updated_target_item_type_icon.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated item type icon {}.", updated_target_item_type_icon.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_item_type_icon));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/item-type-icons/{item_type_icon_id}", axum::routing::get(handle_get_item_type_icon_request))
    .route("/item-type-icons/{item_type_icon_id}", axum::routing::delete(handle_delete_item_type_icon_request))
    .route("/item-type-icons/{item_type_icon_id}", axum::routing::patch(handle_patch_item_type_icon_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
