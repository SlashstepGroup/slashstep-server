/**
 * 
 * Any functionality for /fields/{field_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[path = "./field-choices/mod.rs"]
mod field_choices;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_transaction_middleware}, 
  resources::{
    access_policy::{ActionPermissionLevel, ResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, field::{EditableFieldProperties, Field}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_field_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length, validate_resource_display_name, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}
};

/// GET /fields/{field_id}
/// 
/// Gets a field by its ID.
#[axum::debug_handler]
async fn handle_get_field_request(
  Path(field_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<Field>, HTTPError> {

  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let get_fields_action = get_action_by_name("fields.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_fields_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Field, Some(&target_field.id), &get_fields_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_fields_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Field,
    target_field_id: Some(target_field.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned field {}.", target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_field));

}

/// DELETE /fields/{field_id}
/// 
/// Deletes a field by its ID.
#[axum::debug_handler]
async fn handle_delete_field_request(
  Path(field_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let delete_fields_action = get_action_by_name("fields.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_fields_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Field, Some(&target_field.id), &delete_fields_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_field.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete field: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_fields_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Field,
    target_field_id: Some(target_field.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted field {}.", target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

// //// PATCH /fields/{field_id}
/// 
/// Updates a field by its ID.
#[axum::debug_handler]
async fn handle_patch_field_request(
  Path(field_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableFieldProperties>, JsonRejection>
) -> Result<Json<Field>, HTTPError> {

  let updated_field_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(field_name) = &updated_field_properties.name { 
    
    validate_field_length(field_name, "fields.maximumNameLength", "name", &http_transaction, &state.database_pool).await?;
    validate_resource_name(field_name, "fields.allowedNameRegex", "Field", &http_transaction, &state.database_pool).await?;
  
  };
  if let Some(field_display_name) = &updated_field_properties.display_name { 
    
    validate_field_length(field_display_name, "fields.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;
    validate_resource_display_name(field_display_name, "fields.allowedDisplayNameRegex", "Field", &http_transaction, &state.database_pool).await?;
  
  };
  if let Some(field_description) = &updated_field_properties.description { validate_field_length(field_description, "fields.maximumDescriptionLength", "description", &http_transaction, &state.database_pool).await?; };
  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let original_target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("fields.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Field, Some(&original_target_field.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating field {}...", original_target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_field = match original_target_field.update(&updated_field_properties, &state.database_pool).await {

    Ok(updated_target_field) => updated_target_field,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update field {}: {:?}", original_target_field.id, error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::Field,
    target_field_id: Some(updated_target_field.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated field {}.", updated_target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_field));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/fields/{field_id}", axum::routing::get(handle_get_field_request))
    .route("/fields/{field_id}", axum::routing::delete(handle_delete_field_request))
    .route("/fields/{field_id}", axum::routing::patch(handle_patch_field_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()))
    .merge(field_choices::get_router(state.clone()));
  return router;

}
