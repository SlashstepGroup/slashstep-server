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
#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, field::{EditableFieldProperties, Field}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_field_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}
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

  let http_transaction = http_transaction.clone();
  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_field, &AccessPolicyResourceType::Field, &target_field.id, &http_transaction, &state.database_pool).await?;
  let get_fields_action = get_action_by_name("slashstep.fields.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_fields_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &get_fields_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_fields_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
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
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    Some(&AccessPolicyResourceType::Field),
    &field_id, 
    "slashstep.fields.delete",
    "field",
    &ActionLogEntryTargetResourceType::Field,
    |field_id, database_pool| Box::new(Field::get_by_id(field_id, database_pool))
  ).await;

  return response;

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

  let http_transaction = http_transaction.clone();
  let updated_field_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let original_target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_field, &AccessPolicyResourceType::Field, &original_target_field.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("slashstep.fields.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

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
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
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
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
