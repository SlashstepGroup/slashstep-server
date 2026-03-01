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
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_transaction_middleware}, 
  resources::{
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, item_connection_type::{EditableItemConnectionTypeProperties, ItemConnectionType}, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_item_connection_type_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, validate_field_length, verify_delegate_permissions, verify_principal_permissions}}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

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
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<ItemConnectionType>, HTTPError> {

  let item_connection_type_id = get_uuid_from_string(&item_connection_type_id, "item connection type", &http_transaction, &state.database_pool).await?;
  let target_item_connection_type = get_item_connection_type_by_id(&item_connection_type_id, &http_transaction, &state.database_pool).await?;
  let get_item_connection_types_action = get_action_by_name("itemConnectionTypes.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_item_connection_types_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_item_connection_type, &AccessPolicyResourceType::ItemConnectionType, &target_item_connection_type.id, &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &get_item_connection_types_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_item_connection_types_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnectionType,
    target_item_connection_type_id: Some(target_item_connection_type.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned item connection type {}.", target_item_connection_type.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_item_connection_type));

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
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let item_connection_type_id = get_uuid_from_string(&item_connection_type_id, "item connection type", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    Some(&AccessPolicyResourceType::ItemConnectionType),
    &item_connection_type_id, 
    "itemConnectionTypes.delete",
    "item connection type",
    &ActionLogEntryTargetResourceType::ItemConnectionType,
    |item_connection_type_id, database_pool| Box::new(ItemConnectionType::get_by_id(item_connection_type_id, database_pool))
  ).await;

  return response;

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
  body: Result<Json<EditableItemConnectionTypeProperties>, JsonRejection>
) -> Result<Json<ItemConnectionType>, HTTPError> {

  let item_connection_type_id = get_uuid_from_string(&item_connection_type_id, "item connection type", &http_transaction, &state.database_pool).await?;
  let updated_item_connection_type_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(updated_item_connection_type_display_name) = &updated_item_connection_type_properties.display_name {
    
    validate_field_length(updated_item_connection_type_display_name, "itemConnectionTypes.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;

  }
  if let Some(updated_item_connection_type_inward_description) = &updated_item_connection_type_properties.inward_description {

    validate_field_length(updated_item_connection_type_inward_description, "itemConnectionTypes.maximumDescriptionLength", "inward_description", &http_transaction, &state.database_pool).await?;

  }
  if let Some(updated_item_connection_type_outward_description) = &updated_item_connection_type_properties.outward_description {

    validate_field_length(updated_item_connection_type_outward_description, "itemConnectionTypes.maximumDescriptionLength", "outward_description", &http_transaction, &state.database_pool).await?;

  }
  let original_target_item_connection_type = get_item_connection_type_by_id(&item_connection_type_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_item_connection_type, &AccessPolicyResourceType::ItemConnectionType, &original_target_item_connection_type.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("itemConnectionTypes.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating item connection type {}...", original_target_item_connection_type.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_item_connection_type = match original_target_item_connection_type.update(&updated_item_connection_type_properties, &state.database_pool).await {

    Ok(updated_target_item_connection_type) => updated_target_item_connection_type,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update item connection type {}: {:?}", original_target_item_connection_type.id, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnectionType,
    target_item_connection_type_id: Some(updated_target_item_connection_type.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated item connection type {}.", updated_target_item_connection_type.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_item_connection_type));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/item-connection-types/{item_connection_type_id}", axum::routing::get(handle_get_item_connection_type_request))
    .route("/item-connection-types/{item_connection_type_id}", axum::routing::delete(handle_delete_item_connection_type_request))
    .route("/item-connection-types/{item_connection_type_id}", axum::routing::patch(handle_patch_item_connection_type_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
