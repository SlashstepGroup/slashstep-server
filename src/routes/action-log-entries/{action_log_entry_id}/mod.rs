/**
 * 
 * Any functionality for /action-log-entries/{action_log_entry_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use reqwest::{StatusCode};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{ResourceError, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_authenticated_principal, get_resource_hierarchy, get_uuid_from_string, verify_principal_permissions}}};

#[path = "./access-policies/mod.rs"]
mod access_policies;

async fn get_action_log_entry_from_id(action_log_entry_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ActionLogEntry, HTTPError> {

  let action_log_entry_id = match Uuid::parse_str(&action_log_entry_id) {

    Ok(action_log_entry_id) => action_log_entry_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action log entry ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting action log entry {}...", action_log_entry_id), Some(&http_transaction.id), &database_pool).await.ok();
  
  let action_log_entry = match ActionLogEntry::get_by_id(&action_log_entry_id, &database_pool).await {

    Ok(action_log_entry) => action_log_entry,

    Err(error) => {

      let http_error = match error {

        ResourceError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),

        ResourceError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();

      return Err(http_error);

    }

  };

  return Ok(action_log_entry);

}

/// GET /action-log-entries/{action_log_entry_id}
/// 
/// Gets an action log entry by its ID.
#[axum::debug_handler]
async fn handle_get_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<Json<ActionLogEntry>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let action_log_entry = get_action_log_entry_from_id(&action_log_entry_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&action_log_entry, &AccessPolicyResourceType::ActionLogEntry, &action_log_entry.id, &http_transaction, &state.database_pool).await?;
  let get_action_log_entries_action = get_action_from_name("slashstep.actionLogEntries.get", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &get_action_log_entries_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ActionLogEntry,
    target_action_log_entry_id: Some(action_log_entry.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned action log entry {}.", action_log_entry_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(action_log_entry));

}

/// DELETE /action-log-entries/{action_log_entry_id}
///
/// Deletes an action log entry by its ID.
#[axum::debug_handler]
async fn handle_delete_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let action_log_entry_id = get_uuid_from_string(&action_log_entry_id, "action log entry", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Some(&AccessPolicyResourceType::ActionLogEntry),
    &action_log_entry_id, 
    "slashstep.actionLogEntries.delete",
    "action log entry",
    &ActionLogEntryTargetResourceType::ActionLogEntry,
    |action_log_entry_id, database_pool| Box::new(ActionLogEntry::get_by_id(action_log_entry_id, database_pool))
  ).await;

  return response;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::get(handle_get_action_log_entry_request))
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::delete(handle_delete_action_log_entry_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;