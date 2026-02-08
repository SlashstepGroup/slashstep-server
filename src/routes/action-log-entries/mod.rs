/**
 * 
 * Any functionality for /action-log-entries should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{ResourceError, access_policy::{AccessPolicyResourceType, ActionPermissionLevel, ResourceHierarchy}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_authenticated_principal, get_individual_principal_from_authenticated_principal, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

#[path = "./{action_log_entry_id}/mod.rs"]
mod action_log_entry_id;
#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
pub struct ActionLogEntryListQueryParameters {
  query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListActionLogEntryResponseBody {
  action_log_entries: Vec<ActionLogEntry>,
  total_count: i64
}

/// GET /action-log-entries
/// 
/// Lists action log entries.
#[axum::debug_handler]
async fn handle_list_action_log_entries_request(
  Query(query_parameters): Query<ActionLogEntryListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  // Make sure the principal has access to list resources.
  let http_transaction = http_transaction.clone();
  let list_action_log_entries_action = get_action_by_name("slashstep.actionLogEntries.list", &http_transaction, &state.database_pool).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Server, None)];
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_action_log_entries_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &list_action_log_entries_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Get the list of resources.
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);
  let query = query_parameters.query.unwrap_or("".to_string());
  let action_log_entries = match ActionLogEntry::list(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(actions) => actions,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT, "action log entries"),

        ResourceError::PostgresError(error) => match_db_error(&error, "action log entries"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list action log entries: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting action log entries..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let action_log_entry_count = match ActionLogEntry::count(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(action_log_entry_count) => action_log_entry_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count action log entries: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Server,
    ..Default::default()
  }, &state.database_pool).await.ok();
  let action_list_length = action_log_entries.len();
  ServerLogEntry::success(&format!("Successfully returned {} action log {}.", action_list_length, if action_list_length == 1 { "entry" } else { "entries" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  
  let response_body = ListActionLogEntryResponseBody {
    action_log_entries,
    total_count: action_log_entry_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries", axum::routing::get(handle_list_action_log_entries_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(action_log_entry_id::get_router(state.clone()));
  return router;

}