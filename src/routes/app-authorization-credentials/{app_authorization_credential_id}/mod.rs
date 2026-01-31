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

// #[path = "./access-policies/mod.rs"]
// mod access_policies;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization_credential::AppAuthorizationCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{
    AuthenticatedPrincipal, get_action_from_name, get_app_authorization_credential_from_id, get_authenticated_principal, get_resource_hierarchy, verify_principal_permissions
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

// /// DELETE /app-authorizations/{app_authorization_id}
// /// 
// /// Deletes an app authorization by its ID.
// #[axum::debug_handler]
// async fn handle_delete_app_authorization_request(
//   Path(app_authorization_id): Path<String>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticating_user): Extension<Option<Arc<User>>>,
//   Extension(authenticating_app): Extension<Option<Arc<App>>>
// ) -> Result<StatusCode, HTTPError> {

//   let http_transaction = http_transaction.clone();
//   let target_app_authorization = get_app_authorization_from_id(&app_authorization_id, &http_transaction, &state.database_pool).await?;
//   let resource_hierarchy = get_resource_hierarchy(&target_app_authorization, &AccessPolicyResourceType::AppAuthorization, &target_app_authorization.id, &http_transaction, &state.database_pool).await?;
//   let delete_app_authorizations_action = get_action_from_name("slashstep.appAuthorizations.delete", &http_transaction, &state.database_pool).await?;
//   let authenticated_principal = get_authenticated_principal(&authenticating_user, &authenticating_app)?;
//   verify_principal_permissions(&authenticated_principal, &delete_app_authorizations_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

//   match target_app_authorization.delete(&state.database_pool).await {

//     Ok(_) => {},

//     Err(error) => {

//       let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app authorization: {:?}", error)));
//       http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   }

//   ActionLogEntry::create(&InitialActionLogEntryProperties {
//     action_id: delete_app_authorizations_action.id,
//     http_transaction_id: Some(http_transaction.id),
//     actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
//     actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
//     actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
//     target_resource_type: ActionLogEntryTargetResourceType::AppAuthorization,
//     target_app_authorization_id: Some(target_app_authorization.id),
//     ..Default::default()
//   }, &state.database_pool).await.ok();
//   ServerLogEntry::success(&format!("Successfully deleted app authorization {}.", &app_authorization_id), Some(&http_transaction.id), &state.database_pool).await.ok();

//   return Ok(StatusCode::NO_CONTENT);

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::get(handle_get_app_authorization_credential_request))
    // .route("/app-authorization-credentials/{app_authorization_credential_id}", axum::routing::delete(handle_delete_app_authorization_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}