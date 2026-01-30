use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    DeletableResource,
    access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action::{
      Action, 
      EditableActionProperties
    }, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{
      get_action_from_id, get_action_from_name, get_resource_hierarchy, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions
    }
};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

#[axum::debug_handler]
async fn handle_get_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_action, &AccessPolicyResourceType::Action, &target_action.id, &http_transaction, &mut postgres_client).await?;
  let get_actions_action = get_action_from_name("slashstep.actions.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &get_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(target_action.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action {}.", target_action.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(target_action));

}

#[axum::debug_handler]
async fn handle_patch_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<EditableActionProperties>, JsonRejection>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await.ok();
  let updated_action_properties = match body {

    Ok(updated_action_properties) => updated_action_properties,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  let original_target_action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_action, &AccessPolicyResourceType::Action, &original_target_action.id, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.actions.update", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  ServerLogEntry::trace(&format!("Updating action {}...", action_id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let updated_target_action = match original_target_action.update(&updated_action_properties, &mut postgres_client).await {

    Ok(updated_target_action) => updated_target_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update action: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(updated_target_action.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully updated action {}.", action_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(updated_target_action));

}

#[axum::debug_handler]
async fn handle_delete_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_action, &AccessPolicyResourceType::Action, &target_action.id, &http_transaction, &mut postgres_client).await?;
  let delete_actions_action = get_action_from_name("slashstep.actions.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  match target_action.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete action: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(target_action.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted action {}.", action_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions/{action_id}", axum::routing::get(handle_get_action_request))
    .route("/actions/{action_id}", axum::routing::patch(handle_patch_action_request))
    .route("/actions/{action_id}", axum::routing::delete(handle_delete_action_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;