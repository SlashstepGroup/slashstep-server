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
  AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{
    access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_credential::AppCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{
    AuthenticatedPrincipal, get_action_from_name, get_app_credential_from_id, get_authenticated_principal, get_resource_hierarchy, get_uuid_from_string, verify_principal_permissions
  }}
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
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<Json<AppCredential>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_app_credential = get_app_credential_from_id(&app_credential_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app_credential, &AccessPolicyResourceType::AppCredential, &target_app_credential.id, &http_transaction, &state.database_pool).await?;
  let get_app_credentials_action = get_action_from_name("slashstep.appCredentials.get", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &get_app_credentials_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_app_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
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
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let app_credential_id = get_uuid_from_string(&app_credential_id, "app credential", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Some(&AccessPolicyResourceType::AppCredential),
    &app_credential_id, 
    "slashstep.appCredentials.delete",
    "app credential",
    &ActionLogEntryTargetResourceType::AppCredential,
    |app_credential_id, database_pool| Box::new(AppCredential::get_by_id(app_credential_id, database_pool))
  ).await;

  return response;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-credentials/{app_credential_id}", axum::routing::get(handle_get_app_credential_request))
    .route("/app-credentials/{app_credential_id}", axum::routing::delete(handle_delete_app_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}