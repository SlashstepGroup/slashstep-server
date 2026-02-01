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
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization_credential::AppAuthorizationCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{
    AuthenticatedPrincipal, get_action_from_name, get_app_authorization_credential_from_id, get_authenticated_principal, get_resource_hierarchy, get_uuid_from_string, verify_principal_permissions
  }}
};

/// GET /app-authorization-credentials/{app_authorization_credential_id}
/// 
/// Gets an app authorization credential by its ID.
#[axum::debug_handler]
async fn handle_get_app_authorization_credential_request(
  Path(app_authorization_credential_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  Extension(app): Extension<Option<Arc<App>>>
) -> Result<Json<AppAuthorizationCredential>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_app_authorization_credential = get_app_authorization_credential_from_id(&app_authorization_credential_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app_authorization_credential, &AccessPolicyResourceType::AppAuthorizationCredential, &target_app_authorization_credential.id, &http_transaction, &state.database_pool).await?;
  let get_app_authorizations_action = get_action_from_name("slashstep.appAuthorizationCredentials.get", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&user, &app)?;
  verify_principal_permissions(&authenticated_principal, &get_app_authorizations_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_app_authorizations_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AppAuthorizationCredential,
    target_app_authorization_credential_id: Some(target_app_authorization_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned app authorization credential {}.", target_app_authorization_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_app_authorization_credential));

}

/// DELETE /app-authorizations/{app_authorization_id}
/// 
/// Deletes an app authorization by its ID.
#[axum::debug_handler]
async fn handle_delete_app_authorization_credential_request(
  Path(app_authorization_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let app_authorization_id = get_uuid_from_string(&app_authorization_id, "app authorization credential", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Some(&AccessPolicyResourceType::AppAuthorizationCredential), 
    &app_authorization_id, 
    "slashstep.appAuthorizationCredentials.delete",
    "app authorization credential", 
    &ActionLogEntryTargetResourceType::AppAuthorizationCredential,
    |app_authorization_credential_id, database_pool| Box::new(AppAuthorizationCredential::get_by_id(app_authorization_credential_id, database_pool))
  ).await;

  return response;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::get(handle_get_app_authorization_credential_request))
    .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::delete(handle_delete_app_authorization_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}