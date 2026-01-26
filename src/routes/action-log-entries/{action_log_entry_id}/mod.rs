/**
 * 
 * This module defines the route handlers for specific action log entry resources.
 * Anything to do with /action-log-entries/{action_log_entry_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::AccessPolicyPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryError, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{get_action_from_name, get_resource_hierarchy_for_action_log_entry, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}};

#[path = "./access-policies/mod.rs"]
mod access_policies;

async fn get_action_log_entry_from_id(action_log_entry_id: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ActionLogEntry, HTTPError> {

  let action_log_entry_id = match Uuid::parse_str(&action_log_entry_id) {

    Ok(action_log_entry_id) => action_log_entry_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action log entry ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting action log entry {}...", action_log_entry_id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  
  let action_log_entry = match ActionLogEntry::get_by_id(&action_log_entry_id, &mut postgres_client).await {

    Ok(action_log_entry) => action_log_entry,

    Err(error) => {

      let http_error = match error {

        ActionLogEntryError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),

        ActionLogEntryError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();

      return Err(http_error);

    }

  };

  return Ok(action_log_entry);

}

#[axum::debug_handler]
async fn handle_get_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<ActionLogEntry>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let action_log_entry = get_action_log_entry_from_id(&action_log_entry_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy_for_action_log_entry(&action_log_entry, &http_transaction, &mut postgres_client).await?;
  let get_action_log_entries_action = get_action_from_name("slashstep.actionLogEntries.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &get_action_log_entries_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::ActionLogEntry,
    target_action_log_entry_id: Some(action_log_entry.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action log entry {}.", action_log_entry_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(action_log_entry));

}

#[axum::debug_handler]
async fn handle_delete_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_action_log_entry = get_action_log_entry_from_id(&action_log_entry_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy_for_action_log_entry(&target_action_log_entry, &http_transaction, &mut postgres_client).await?;
  let delete_action_log_entries_action = get_action_from_name("slashstep.actionLogEntries.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_action_log_entries_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  match target_action_log_entry.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete action log entry: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::ActionLogEntry,
    target_action_log_entry_id: Some(target_action_log_entry.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted action log entry {}.", action_log_entry_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::get(handle_get_action_log_entry_request))
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::delete(handle_delete_action_log_entry_request))
    .merge(access_policies::get_router(state.clone()))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;