/**
 * 
 * Any functionality for /app-credentials/{app_credential_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use reqwest::StatusCode;
use crate::{
  AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{
    access_policy::{ResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, app_credential::AppCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, utilities::route_handler_utilities::{
    get_action_by_name, get_action_log_entry_expiration_timestamp, get_app_credential_by_id, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions
  }
};

/// GET /app-credentials/{app_credential_id}
/// 
/// Gets an app credential by its ID.
#[axum::debug_handler]
async fn handle_get_app_credential_request(
  Path(app_credential_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<AppCredential>, HTTPError> {

  let app_credential_id = get_uuid_from_string(&app_credential_id, "app credential", &http_transaction, &state.database_pool).await?;
  let target_app_credential = get_app_credential_by_id(&app_credential_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app_credential, &ResourceType::AppCredential, &target_app_credential.id, &http_transaction, &state.database_pool).await?;
  let get_app_credentials_action = get_action_by_name("appCredentials.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_app_credentials_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &get_app_credentials_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_app_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AppCredential,
    target_app_credential_id: Some(target_app_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned app credential {}.", target_app_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_app_credential));

}

/// DELETE /app-credentials/{app_credential_id}
/// 
/// Deletes an app credential by its ID.
#[axum::debug_handler]
async fn handle_delete_app_credential_request(
  Path(app_credential_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let app_credential_id = get_uuid_from_string(&app_credential_id, "app credential", &http_transaction, &state.database_pool).await?;
  let target_app_credential = get_app_credential_by_id(&app_credential_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app_credential, &ResourceType::AppCredential, &target_app_credential.id, &http_transaction, &state.database_pool).await?;
  let delete_app_credentials_action = get_action_by_name("appCredentials.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_app_credentials_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &delete_app_credentials_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_app_credential.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app credential: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_app_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AppCredential,
    target_app_credential_id: Some(target_app_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted app credential {}.", target_app_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-credentials/{app_credential_id}", axum::routing::get(handle_get_app_credential_request))
    .route("/app-credentials/{app_credential_id}", axum::routing::delete(handle_delete_app_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}