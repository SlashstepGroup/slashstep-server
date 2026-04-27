/**
 * 
 * Any functionality for /users/{user_id} should be handled here.
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
    ResourceType, access_policy::ActionPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::{EditableUserProperties, EditableUserPropertiesRequestBody, User}
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_user_by_id, get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[path = "./oauth-authorizations/mod.rs"]
mod oauth_authorizations;
mod password;
#[cfg(test)]
mod tests;

/// GET /users/{user_id}
/// 
/// Gets a user by its ID.
#[axum::debug_handler]
async fn handle_get_user_request(
  Path(user_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<User>, HTTPError> {

  let user_id = get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
  let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
  let get_users_action = get_action_by_name("users.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_users_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::User, Some(&target_user.id), &get_users_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_users_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::User,
    target_user_id: Some(target_user.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned user {}.", target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_user));

}

/// DELETE /users/{user_id}
/// 
/// Deletes an user by its ID.
#[axum::debug_handler]
async fn handle_delete_user_request(
  Path(user_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let user_id = get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
  let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
  let delete_users_action = get_action_by_name("users.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_users_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::User, Some(&target_user.id), &delete_users_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  if let Err(error) = target_user.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete user: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_users_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::User,
    target_user_id: Some(target_user.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted user {}.", target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /users/{user_id}
/// 
/// Updates an user by its ID.
#[axum::debug_handler]
async fn handle_patch_user_request(
  Path(user_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableUserPropertiesRequestBody>, JsonRejection>
) -> Result<Json<User>, HTTPError> {

  let user_id = get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
  let updated_user_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(Some(username)) = &updated_user_properties.username {

    validate_field_length(username, "users.maximumNameLength", "username", &http_transaction, &state.database_pool).await?;
    validate_resource_name(username, "users.allowedNameRegex", "user", &http_transaction, &state.database_pool).await?;

  }

  if let Some(Some(display_name)) = &updated_user_properties.display_name {

    validate_field_length(display_name, "users.maximumDisplayNameLength", "display name", &http_transaction, &state.database_pool).await?;

  }

  let original_target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("users.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::User, Some(&original_target_user.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  println!("{:?}", updated_user_properties);
  ServerLogEntry::trace(&format!("Updating user {}...", original_target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_user = match original_target_user.update(&EditableUserProperties {
    username: updated_user_properties.username.clone(),
    display_name: updated_user_properties.display_name.clone(),
    hashed_password: None
  }, &state.database_pool).await {

    Ok(updated_target_user) => updated_target_user,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update user: {:?}", error)));
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
    target_resource_type: ResourceType::User,
    target_user_id: Some(updated_target_user.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated user {}.", updated_target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_user));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/users/{user_id}", axum::routing::get(handle_get_user_request))
    .route("/users/{user_id}", axum::routing::delete(handle_delete_user_request))
    .route("/users/{user_id}", axum::routing::patch(handle_patch_user_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()))
    .merge(password::get_router(state.clone()));
  return router;

}
