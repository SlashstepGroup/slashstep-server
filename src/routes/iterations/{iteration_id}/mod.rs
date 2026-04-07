/**
 * 
 * Any functionality for /iterations/{iteration_id} should be handled here.
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
    ResourceType, access_policy::ActionPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, iteration::{EditableIterationProperties, Iteration}, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_iteration_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length, verify_delegate_permissions, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /iterations/{iteration_id}
/// 
/// Gets an iteration by its ID.
#[axum::debug_handler]
async fn handle_get_iteration_request(
  Path(iteration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<Iteration>, HTTPError> {

  let iteration_id = get_uuid_from_string(&iteration_id, "iteration", &http_transaction, &state.database_pool).await?;
  let target_iteration = get_iteration_by_id(&iteration_id, &http_transaction, &state.database_pool).await?;
  let get_iterations_action = get_action_by_name("iterations.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_iterations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Iteration, Some(&target_iteration.id), &get_iterations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_iterations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Iteration,
    target_iteration_id: Some(target_iteration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned iteration {}.", target_iteration.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_iteration));

}

/// DELETE /iterations/{iteration_id}
/// 
/// Deletes an iteration by its ID.
#[axum::debug_handler]
async fn handle_delete_iteration_request(
  Path(iteration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let iteration_id = get_uuid_from_string(&iteration_id, "iteration", &http_transaction, &state.database_pool).await?;
  let target_iteration = get_iteration_by_id(&iteration_id, &http_transaction, &state.database_pool).await?;
  let delete_iterations_action = get_action_by_name("iterations.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_iterations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Iteration, Some(&target_iteration.id), &delete_iterations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  if let Err(error) = target_iteration.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete iteration: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_iterations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Iteration,
    target_iteration_id: Some(target_iteration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted iteration {}.", target_iteration.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /iterations/{iteration_id}
/// 
/// Updates an iteration by its ID.
#[axum::debug_handler]
async fn handle_patch_iteration_request(
  Path(iteration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableIterationProperties>, JsonRejection>
) -> Result<Json<Iteration>, HTTPError> {

  let iteration_id = get_uuid_from_string(&iteration_id, "iteration", &http_transaction, &state.database_pool).await?;
  let updated_iteration_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  if let Some(display_name) = &updated_iteration_properties.display_name {

    validate_field_length(display_name, "iterations.maximumDisplayNameLength", "display name", &http_transaction, &state.database_pool).await?;

  }

  let original_target_iteration = get_iteration_by_id(&iteration_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("iterations.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Iteration, Some(&original_target_iteration.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating iteration {}...", original_target_iteration.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_iteration = match original_target_iteration.update(&updated_iteration_properties, &state.database_pool).await {

    Ok(updated_target_iteration) => updated_target_iteration,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update iteration: {:?}", error)));
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
    target_resource_type: ResourceType::Iteration,
    target_iteration_id: Some(updated_target_iteration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated iteration {}.", updated_target_iteration.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_iteration));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/iterations/{iteration_id}", axum::routing::get(handle_get_iteration_request))
    .route("/iterations/{iteration_id}", axum::routing::delete(handle_delete_iteration_request))
    .route("/iterations/{iteration_id}", axum::routing::patch(handle_patch_iteration_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
