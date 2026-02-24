/**
 * 
 * Any functionality for /actions/{action_id} should be handled here.
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
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action::{
      Action, 
      EditableActionProperties
    }, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{
      AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, validate_action_display_name_length, validate_action_name, validate_action_name_length, verify_delegate_permissions, verify_principal_permissions
    }}
};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

/// GET /actions/{action_id}
/// 
/// Gets an action by its ID.
#[axum::debug_handler]
async fn handle_get_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_action = get_action_by_id(&action_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_action, &AccessPolicyResourceType::Action, &target_action.id, &http_transaction, &state.database_pool).await?;
  let get_actions_action = get_action_by_name("actions.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_actions_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &get_actions_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(target_action.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action {}.", target_action.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_action));

}

/// PATCH /actions/{action_id}
/// 
/// Updates an action by its ID.
#[axum::debug_handler]
async fn handle_patch_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableActionProperties>, JsonRejection>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let updated_action_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(updated_action_name) = &updated_action_properties.name { validate_action_name_length(updated_action_name, &http_transaction, &state.database_pool).await?; };
  if let Some(updated_action_display_name) = &updated_action_properties.display_name { validate_action_display_name_length(updated_action_display_name, &http_transaction, &state.database_pool).await?; };
  if let Some(updated_action_name) = &updated_action_properties.name { validate_action_name(updated_action_name, &http_transaction, &state.database_pool).await?; };
  let original_target_action = get_action_by_id(&action_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_action, &AccessPolicyResourceType::Action, &original_target_action.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("actions.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating action {}...", action_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_action = match original_target_action.update(&updated_action_properties, &state.database_pool).await {

    Ok(updated_target_action) => updated_target_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update action: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(updated_target_action.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated action {}.", action_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_action));

}

/// DELETE /actions/{action_id}
/// 
/// Deletes an action by its ID.
#[axum::debug_handler]
async fn handle_delete_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let action_log_entry_id = get_uuid_from_string(&action_id, "action", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    Some(&AccessPolicyResourceType::Action),
    &action_log_entry_id, 
    "actions.delete",
    "action",
    &ActionLogEntryTargetResourceType::Action,
    |action_id, database_pool| Box::new(Action::get_by_id(action_id, database_pool))
  ).await;

  return response;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions/{action_id}", axum::routing::get(handle_get_action_request))
    .route("/actions/{action_id}", axum::routing::patch(handle_patch_action_request))
    .route("/actions/{action_id}", axum::routing::delete(handle_delete_action_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;