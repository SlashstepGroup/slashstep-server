/**
 * 
 * Any functionality for /field-values/{field_value_id} should be handled here.
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
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, EditableAppProperties}, app_authorization::AppAuthorization, field_value::FieldValue, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_app_by_id, get_authenticated_principal, get_field_value_by_id, get_resource_by_id, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /field-values/{field_value_id}
/// 
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_field_value_request(
  Path(field_value_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<FieldValue>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let field_value_id = get_uuid_from_string(&field_value_id, "field value", &http_transaction, &state.database_pool).await?;
  let target_field_value = get_field_value_by_id(&field_value_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_field_value, &AccessPolicyResourceType::FieldValue, &target_field_value.id, &http_transaction, &state.database_pool).await?;
  let get_field_values_action = get_action_by_name("fieldValues.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_field_values_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &get_field_values_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_field_values_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::FieldValue,
    target_field_value_id: Some(target_field_value.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned field value {}.", target_field_value.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_field_value));

}

/// DELETE /field-values/{field_value_id}
/// 
/// Deletes a field value by its ID.
#[axum::debug_handler]
async fn handle_delete_field_value_request(
  Path(field_value_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let field_value_id = get_uuid_from_string(&field_value_id, "field value", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    Some(&AccessPolicyResourceType::FieldValue),
    &field_value_id, 
    "fieldValues.delete",
    "field value",
    &ActionLogEntryTargetResourceType::FieldValue,
    |field_value_id, database_pool| Box::new(FieldValue::get_by_id(field_value_id, database_pool))
  ).await;

  return response;

}

// /// PATCH /field-values/{field_value_id}
// /// 
// /// Updates an app by its ID.
// #[axum::debug_handler]
// async fn handle_patch_app_request(
//   Path(field_value_id): Path<String>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>,
//   Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
//   body: Result<Json<EditableAppProperties>, JsonRejection>
// ) -> Result<Json<App>, HTTPError> {

//   let http_transaction = http_transaction.clone();

//   ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
//   let updated_app_properties = match body {

//     Ok(updated_app_properties) => updated_app_properties,

//     Err(error) => {

//       let http_error = match error {

//         JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

//         JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

//         JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

//         JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

//         _ => HTTPError::InternalServerError(Some(error.to_string()))

//       };
      
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   };

//   let original_target_field = get_app_by_id(&field_value_id, &http_transaction, &state.database_pool).await?;
//   let resource_hierarchy = get_resource_hierarchy(&original_target_field, &AccessPolicyResourceType::App, &original_target_field.id, &http_transaction, &state.database_pool).await?;
//   let update_access_policy_action = get_action_by_name("apps.update", &http_transaction, &state.database_pool).await?;
//   verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
//   let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
//   verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

//   ServerLogEntry::trace(&format!("Updating authenticated_app {}...", original_target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();
//   let updated_target_action = match original_target_field.update(&updated_app_properties, &state.database_pool).await {

//     Ok(updated_target_action) => updated_target_action,

//     Err(error) => {

//       let http_error = HTTPError::InternalServerError(Some(format!("Failed to update authenticated_app: {:?}", error)));
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   };

//   ActionLogEntry::create(&InitialActionLogEntryProperties {
//     action_id: update_access_policy_action.id,
//     http_transaction_id: Some(http_transaction.id),
//     actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
//     actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
//     actor_field_value_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
//     target_resource_type: ActionLogEntryTargetResourceType::Action,
//     target_action_id: Some(updated_target_action.id),
//     ..Default::default()
//   }, &state.database_pool).await.ok();
//   ServerLogEntry::success(&format!("Successfully updated action {}.", updated_target_action.id), Some(&http_transaction.id), &state.database_pool).await.ok();

//   return Ok(Json(updated_target_action));

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/field-values/{field_value_id}", axum::routing::get(handle_get_field_value_request))
    .route("/field-values/{field_value_id}", axum::routing::delete(handle_delete_field_value_request))
    // .route("/field-values/{field_value_id}", axum::routing::patch(handle_patch_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
