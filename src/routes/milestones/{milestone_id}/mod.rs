/**
 * 
 * Any functionality for /milestones/{milestone_id} should be handled here.
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
    ResourceType, access_policy::{ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, milestone::{EditableMilestoneProperties, Milestone}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_milestone_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, validate_decimal_is_within_range, validate_field_length, verify_delegate_permissions, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /milestones/{milestone_id}
/// 
/// Gets a milestone by its ID.
#[axum::debug_handler]
async fn handle_get_milestone_request(
  Path(milestone_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<Milestone>, HTTPError> {

  let milestone_id = get_uuid_from_string(&milestone_id, "milestone", &http_transaction, &state.database_pool).await?;
  let target_milestone = get_milestone_by_id(&milestone_id, &http_transaction, &state.database_pool).await?;
  let get_milestones_action = get_action_by_name("milestones.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_milestones_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Milestone, Some(&target_milestone.id), &get_milestones_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_milestones_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Milestone,
    target_milestone_id: Some(target_milestone.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned milestone {}.", target_milestone.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_milestone));

}

/// DELETE /milestones/{milestone_id}
/// 
/// Deletes a milestone by its ID.
#[axum::debug_handler]
async fn handle_delete_milestone_request(
  Path(milestone_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let milestone_id = get_uuid_from_string(&milestone_id, "milestone", &http_transaction, &state.database_pool).await?;
  let target_milestone = get_milestone_by_id(&milestone_id, &http_transaction, &state.database_pool).await?;
  let delete_milestones_action = get_action_by_name("milestones.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_milestones_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Milestone, Some(&target_milestone.id), &delete_milestones_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_milestone.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete milestone: {:?}", error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_milestones_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Milestone,
    target_milestone_id: Some(target_milestone.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully deleted milestone {}.", target_milestone.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /milestones/{milestone_id}
/// 
/// Updates a milestone by its ID.
#[axum::debug_handler]
async fn handle_patch_milestone_request(
  Path(milestone_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableMilestoneProperties>, JsonRejection>
) -> Result<Json<Milestone>, HTTPError> {

  let updated_milestone_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(Some(milestone_text_value)) = &updated_milestone_properties.text_value { 

    validate_field_length(milestone_text_value, "milestones.maximumTextValueLength", "text_value", &http_transaction, &state.database_pool).await?;

  }
  if let Some(Some(milestone_number_value)) = &updated_milestone_properties.number_value {

    validate_decimal_is_within_range(milestone_number_value, "milestones.minimumNumberValue", "milestones.maximumNumberValue", "number_value", &http_transaction, &state.database_pool).await?;

  }
  let milestone_id = get_uuid_from_string(&milestone_id, "milestone", &http_transaction, &state.database_pool).await?;
  let original_target_milestone = get_milestone_by_id(&milestone_id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("milestones.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Milestone, Some(&original_target_milestone.id), &update_access_policy_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating milestone {}...", original_target_milestone.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_milestone = match original_target_milestone.update(&updated_milestone_properties, &state.database_pool).await {

    Ok(updated_target_milestone) => updated_target_milestone,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update milestone {}: {:?}", original_target_milestone.id, error)));
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
    target_resource_type: ResourceType::Milestone,
    target_milestone_id: Some(updated_target_milestone.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated milestone {}.", updated_target_milestone.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_milestone));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/milestones/{milestone_id}", axum::routing::get(handle_get_milestone_request))
    .route("/milestones/{milestone_id}", axum::routing::delete(handle_delete_milestone_request))
    .route("/milestones/{milestone_id}", axum::routing::patch(handle_patch_milestone_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
