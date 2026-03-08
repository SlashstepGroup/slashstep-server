/**
 * 
 * Any functionality for /item-connections/{item_connection_id} should be handled here.
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
    access_policy::{ActionPermissionLevel, ResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, item_connection::{EditableItemConnectionProperties, ItemConnection}, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_item_connection_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions, verify_principal_permissions}
};

// #[path = "./access-policies/mod.rs"]
// mod access_policies;
#[cfg(test)]
mod tests;

/// GET /item-connections/{item_connection_id}
/// 
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_item_connection_request(
  Path(item_connection_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<ItemConnection>, HTTPError> {

  let item_connection_id = get_uuid_from_string(&item_connection_id, "item connection", &http_transaction, &state.database_pool).await?;
  let target_item_connection = get_item_connection_by_id(&item_connection_id, &http_transaction, &state.database_pool).await?;
  let get_item_connections_action = get_action_by_name("itemConnections.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_item_connections_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemConnection, Some(&target_item_connection.id), &get_item_connections_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_item_connections_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnection,
    target_item_connection_id: Some(target_item_connection.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned item connection {}.", target_item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_item_connection));

}

/// DELETE /item-connections/{item_connection_id}
/// 
/// Deletes an item connection by its ID.
#[axum::debug_handler]
async fn handle_delete_item_connection_request(
  Path(item_connection_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let item_connection_id = get_uuid_from_string(&item_connection_id, "item connection", &http_transaction, &state.database_pool).await?;
  let target_item_connection = get_item_connection_by_id(&item_connection_id, &http_transaction, &state.database_pool).await?;
  let delete_item_connections_action = get_action_by_name("itemConnections.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_item_connections_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemConnection, Some(&target_item_connection.id), &delete_item_connections_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  if let Err(error) = target_item_connection.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete item connection: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_item_connections_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnection,
    target_item_connection_id: Some(target_item_connection.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted item connection {}.", target_item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /item-connections/{item_connection_id}
/// 
/// Updates an item connection by its ID.
#[axum::debug_handler]
async fn handle_patch_item_connection_request(
  Path(item_connection_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableItemConnectionProperties>, JsonRejection>
) -> Result<Json<ItemConnection>, HTTPError> {

  let item_connection_id = get_uuid_from_string(&item_connection_id, "item connection", &http_transaction, &state.database_pool).await?;
  let updated_item_connection_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  let original_target_item_connection = get_item_connection_by_id(&item_connection_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("itemConnections.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ItemConnection, Some(&original_target_item_connection.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating item connection {}...", original_target_item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_item_connection = match original_target_item_connection.update(&updated_item_connection_properties, &state.database_pool).await {

    Ok(updated_target_item_connection) => updated_target_item_connection,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update item connection: {:?}", error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnection,
    target_item_connection_id: Some(updated_target_item_connection.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated item connection {}.", updated_target_item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_item_connection));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/item-connections/{item_connection_id}", axum::routing::get(handle_get_item_connection_request))
    .route("/item-connections/{item_connection_id}", axum::routing::delete(handle_delete_item_connection_request))
    .route("/item-connections/{item_connection_id}", axum::routing::patch(handle_patch_item_connection_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
