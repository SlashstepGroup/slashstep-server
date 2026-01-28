use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, IndividualPrincipal}, action::{Action, ActionError, DEFAULT_MAXIMUM_ACTION_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, match_db_error, match_slashstepql_error, verify_user_permissions}}};

#[path = "./{action_id}/mod.rs"]
pub mod action_id;

#[derive(Debug, Deserialize)]
pub struct ActionListQueryParameters {
  query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListActionResponseBody {
  actions: Vec<Action>,
  total_count: i64
}

#[axum::debug_handler]
async fn handle_list_actions_request(
  Query(query_parameters): Query<ActionListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let list_actions_action = get_action_from_name("slashstep.actions.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  verify_user_permissions(&user, &list_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  let query = query_parameters.query.unwrap_or("".to_string());
  let actions = match Action::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(actions) => actions,

    Err(error) => {

      let http_error = match error {

        ActionError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_ACTION_LIST_LIMIT, "actions"),

        ActionError::PostgresError(error) => match_db_error(&error, "actions"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list actions: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting actions..."), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let action_count = match Action::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(action_count) => action_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count actions: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await.ok();
  let action_list_length = actions.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", action_list_length, if action_list_length == 1 { "action" } else { "actions" }), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let response_body = ListActionResponseBody {
    actions,
    total_count: action_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions", axum::routing::get(handle_list_actions_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(action_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;