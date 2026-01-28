use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{ResourceError, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, IndividualPrincipal, ResourceHierarchy}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, match_db_error, match_slashstepql_error, verify_user_permissions}};

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

#[axum::debug_handler]
async fn handle_list_action_log_entries_request(
  Query(query_parameters): Query<ActionLogEntryListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let list_action_log_entries_action = get_action_from_name("slashstep.actionLogEntries.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  verify_user_permissions(&user, &list_action_log_entries_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  let query = query_parameters.query.unwrap_or("".to_string());
  let action_log_entries = match ActionLogEntry::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(actions) => actions,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT, "action log entries"),

        ResourceError::PostgresError(error) => match_db_error(&error, "action log entries"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list action log entries: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting action log entries..."), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let action_log_entry_count = match ActionLogEntry::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(action_log_entry_count) => action_log_entry_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count action log entries: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_action_log_entries_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await.ok();
  let action_list_length = action_log_entries.len();
  ServerLogEntry::success(&format!("Successfully returned {} action log {}.", action_list_length, if action_list_length == 1 { "entry" } else { "entries" }), Some(&http_transaction.id), &mut postgres_client).await.ok();
  
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
    .merge(action_log_entry_id::get_router(state.clone()));
  return router;

}