/**
 * 
 * Any functionality for /configurations/{configuration_id} should be handled here.
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
    access_policy::{ActionPermissionLevel, ResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, configuration::{Configuration, EditableConfigurationProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_configuration_by_id, get_principal_type_and_id_from_principal, get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /configurations/{configuration_id}
/// 
/// Gets an configuration by its ID.
#[axum::debug_handler]
async fn handle_get_configuration_request(
  Path(configuration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<Configuration>, HTTPError> {

  let configuration_id = get_uuid_from_string(&configuration_id, "configuration", &http_transaction, &state.database_pool).await?;
  let target_configuration = get_configuration_by_id(&configuration_id, &http_transaction, &state.database_pool).await?;
  let get_configurations_action = get_action_by_name("configurations.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_configurations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Configuration, Some(&target_configuration.id), &get_configurations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_configurations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Configuration,
    target_configuration_id: Some(target_configuration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned configuration {}.", target_configuration.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_configuration));

}

/// DELETE /configurations/{configuration_id}
/// 
/// Deletes a configuration by its ID.
#[axum::debug_handler]
async fn handle_delete_configuration_request(
  Path(configuration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let configuration_id = get_uuid_from_string(&configuration_id, "configuration", &http_transaction, &state.database_pool).await?;
  let target_configuration = get_configuration_by_id(&configuration_id, &http_transaction, &state.database_pool).await?;
  let delete_configurations_action = get_action_by_name("configurations.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_configurations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Configuration, Some(&target_configuration.id), &delete_configurations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_configuration.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete configuration: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_configurations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Configuration,
    target_configuration_id: Some(target_configuration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted configuration {}.", target_configuration.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /configurations/{configuration_id}
/// 
/// Updates a configuration by its ID.
#[axum::debug_handler]
async fn handle_patch_configuration_request(
  Path(configuration_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableConfigurationProperties>, JsonRejection>
) -> Result<Json<Configuration>, HTTPError> {


  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_configuration_properties = match body {

    Ok(updated_configuration_properties) => updated_configuration_properties,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let configuration_id = get_uuid_from_string(&configuration_id, "configuration", &http_transaction, &state.database_pool).await?;
  let original_target_configuration = get_configuration_by_id(&configuration_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("configurations.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Configuration, Some(&original_target_configuration.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating authenticated_configuration {}...", original_target_configuration.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_configuration = match original_target_configuration.update(&updated_configuration_properties, &state.database_pool).await {

    Ok(updated_target_configuration) => updated_target_configuration,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update configuration: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Configuration,
    target_configuration_id: Some(updated_target_configuration.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated configuration {}.", updated_target_configuration.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_configuration));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/configurations/{configuration_id}", axum::routing::get(handle_get_configuration_request))
    .route("/configurations/{configuration_id}", axum::routing::delete(handle_delete_configuration_request))
    .route("/configurations/{configuration_id}", axum::routing::patch(handle_patch_configuration_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
