/**
 * 
 * Any functionality for /app-authorization-credentials/{app_authorization_credential_id} should be handled here.
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
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_transaction_middleware}, 
  resources::{
    ResourceType, access_policy::{ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{
    get_action_by_name, get_action_log_entry_expiration_timestamp, get_app_authorization_credential_by_id, get_principal_type_and_id_from_principal, get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions, verify_principal_permissions
  }
};

/// GET /app-authorization-credentials/{app_authorization_credential_id}
/// 
/// Gets an app authorization credential by its ID.
#[axum::debug_handler]
async fn handle_get_app_authorization_credential_request(
  Path(app_authorization_credential_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<AppAuthorizationCredential>, HTTPError> {

  let app_authorization_credential_id = get_uuid_from_string(&app_authorization_credential_id, "app authorization credential", &http_transaction, &state.database_pool).await?;
  let target_app_authorization_credential = get_app_authorization_credential_by_id(&app_authorization_credential_id, &http_transaction, &state.database_pool).await?;
  let get_app_authorizations_action = get_action_by_name("appAuthorizationCredentials.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_app_authorizations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::AppAuthorizationCredential, Some(&target_app_authorization_credential.id), &get_app_authorizations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_app_authorizations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::AppAuthorizationCredential,
    target_app_authorization_credential_id: Some(target_app_authorization_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned app authorization credential {}.", target_app_authorization_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_app_authorization_credential));

}

/// DELETE /app-authorization-credentials/{app_authorization_credential_id}
/// 
/// Deletes an app authorization credential by its ID.
#[axum::debug_handler]
async fn handle_delete_app_authorization_credential_request(
  Path(app_authorization_credential_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let app_authorization_credential_id = get_uuid_from_string(&app_authorization_credential_id, "app authorization credential", &http_transaction, &state.database_pool).await?;
  let target_app_authorization_credential = get_app_authorization_credential_by_id(&app_authorization_credential_id, &http_transaction, &state.database_pool).await?;
  let delete_app_authorization_credentials_action = get_action_by_name("appAuthorizationCredentials.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_app_authorization_credentials_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::AppAuthorizationCredential, Some(&target_app_authorization_credential.id), &delete_app_authorization_credentials_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_app_authorization_credential.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app authorization credential: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_app_authorization_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::AppAuthorizationCredential,
    target_app_authorization_credential_id: Some(target_app_authorization_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted app authorization credential {}.", target_app_authorization_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::get(handle_get_app_authorization_credential_request))
    .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::delete(handle_delete_app_authorization_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}