/**
 * 
 * Any functionality for /action-log-entries/{action_log_entry_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use reqwest::{StatusCode};
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{access_policy::{ActionPermissionLevel, ResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_by_id, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions, verify_principal_permissions}};

#[path = "./access-policies/mod.rs"]
mod access_policies;

/// GET /action-log-entries/{action_log_entry_id}
/// 
/// Gets an action log entry by its ID.
#[axum::debug_handler]
async fn handle_get_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<ActionLogEntry>, HTTPError> {

  let action_log_entry_id = get_uuid_from_string(&action_log_entry_id, "action log entry", &http_transaction, &state.database_pool).await?;
  let action_log_entry = get_action_log_entry_by_id(&action_log_entry_id, &http_transaction, &state.database_pool).await?;
  let get_action_log_entries_action = get_action_by_name("actionLogEntries.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_action_log_entries_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ActionLogEntry, Some(&action_log_entry_id), &get_action_log_entries_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ActionLogEntry,
    target_action_log_entry_id: Some(action_log_entry.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action log entry {}.", action_log_entry_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(action_log_entry));

}

/// DELETE /action-log-entries/{action_log_entry_id}
///
/// Deletes an action log entry by its ID.
#[axum::debug_handler]
async fn handle_delete_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let action_log_entry_id = get_uuid_from_string(&action_log_entry_id, "action log entry", &http_transaction, &state.database_pool).await?;
  let target_action_log_entry = get_action_log_entry_by_id(&action_log_entry_id, &http_transaction, &state.database_pool).await?;
  let delete_resources_action = get_action_by_name("actionLogEntries.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::ActionLogEntry, Some(&action_log_entry_id), &delete_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_action_log_entry.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete action log entry {}: {:?}", target_action_log_entry.id, error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ActionLogEntry,
    target_action_log_entry_id: Some(target_action_log_entry.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted action log entry {}.", target_action_log_entry.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::get(handle_get_action_log_entry_request))
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::delete(handle_delete_action_log_entry_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;