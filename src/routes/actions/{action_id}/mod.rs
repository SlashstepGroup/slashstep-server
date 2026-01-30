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
    DeletableResource, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action::{
      Action, 
      EditableActionProperties
    }, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{
      AuthenticatedPrincipal, get_action_from_id, get_action_from_name, get_authenticated_principal, get_resource_hierarchy, map_postgres_error_to_http_error, verify_principal_permissions
    }
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
  Extension(user): Extension<Option<Arc<User>>>,
  Extension(app): Extension<Option<Arc<App>>>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_action = get_action_from_id(&action_id, &http_transaction, &postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_action, &AccessPolicyResourceType::Action, &target_action.id, &http_transaction, &postgres_client).await?;
  let get_actions_action = get_action_from_name("slashstep.actions.get", &http_transaction, &postgres_client).await?;
  let authenticated_principal = get_authenticated_principal(&user, &app)?;
  verify_principal_permissions(&authenticated_principal, &get_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &postgres_client).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(target_action.id),
    ..Default::default()
  }, &postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action {}.", target_action.id), Some(&http_transaction.id), &postgres_client).await.ok();

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
  Extension(user): Extension<Option<Arc<User>>>,
  Extension(app): Extension<Option<Arc<App>>>,
  body: Result<Json<EditableActionProperties>, JsonRejection>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &postgres_client).await.ok();
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
      
      http_error.print_and_save(Some(&http_transaction.id), &postgres_client).await.ok();
      return Err(http_error);

    }

  };

  let original_target_action = get_action_from_id(&action_id, &http_transaction, &postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_action, &AccessPolicyResourceType::Action, &original_target_action.id, &http_transaction, &postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.actions.update", &http_transaction, &postgres_client).await?;
  let authenticated_principal = get_authenticated_principal(&user, &app)?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &postgres_client).await?;

  ServerLogEntry::trace(&format!("Updating action {}...", action_id), Some(&http_transaction.id), &postgres_client).await.ok();
  let updated_target_action = match original_target_action.update(&updated_action_properties, &postgres_client).await {

    Ok(updated_target_action) => updated_target_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update action: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(updated_target_action.id),
    ..Default::default()
  }, &postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully updated action {}.", action_id), Some(&http_transaction.id), &postgres_client).await.ok();

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
  Extension(user): Extension<Option<Arc<User>>>,
  Extension(app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_action = get_action_from_id(&action_id, &http_transaction, &postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_action, &AccessPolicyResourceType::Action, &target_action.id, &http_transaction, &postgres_client).await?;
  let delete_actions_action = get_action_from_name("slashstep.actions.delete", &http_transaction, &postgres_client).await?;
  let authenticated_principal = get_authenticated_principal(&user, &app)?;
  verify_principal_permissions(&authenticated_principal, &delete_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &postgres_client).await?;

  match target_action.delete(&postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete action: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &postgres_client).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(target_action.id),
    ..Default::default()
  }, &postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted action {}.", action_id), Some(&http_transaction.id), &postgres_client).await.ok();

  return Ok(StatusCode::NO_CONTENT);

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