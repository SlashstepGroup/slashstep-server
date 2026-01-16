use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, IndividualPrincipal}, action::{Action, ActionError, DEFAULT_MAXIMUM_ACTION_LIST_LIMIT}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}, slashstepql::SlashstepQLError}};

#[path = "./{action_id}/mod.rs"]
mod action_id;

#[derive(Debug, Deserialize)]
pub struct AccessPolicyListQueryParameters {
  query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListActionResponseBody {
  actions: Vec<Action>,
  total_count: i64
}

#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Query(query_parameters): Query<AccessPolicyListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let action = get_action_from_name("slashstep.actions.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  verify_user_permissions(&user, &action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  let query = query_parameters.query.unwrap_or("".to_string());
  let actions = match Action::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(access_policies) => access_policies,

    Err(error) => {

      let http_error = match error {

        ActionError::SlashstepQLError(error) => match error {

          SlashstepQLError::SlashstepQLInvalidLimitError(error) => HTTPError::UnprocessableEntity(Some(format!("The provided limit must be zero or a positive integer of {} or less. You provided {}.", DEFAULT_MAXIMUM_ACTION_LIST_LIMIT, error.limit_string))), // TODO: Make this configurable through resource policies.

          SlashstepQLError::InvalidFieldError(field) => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid. The field \"{}\" is not allowed.", field))),

          SlashstepQLError::InvalidQueryError(()) => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid."))),

          _ => HTTPError::InternalServerError(Some(format!("Failed to list access policies: {:?}", error)))

        },

        _ => HTTPError::InternalServerError(Some(format!("Failed to list access policies: {:?}", error)))

      };

      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Counting actions..."), Some(&http_transaction.id), &mut postgres_client).await;
  let access_policy_count = match Action::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(access_policy_count) => access_policy_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count access policies: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let action_list_length = actions.len();
  let _ = ServerLogEntry::success(&format!("Successfully returned {} access {}.", action_list_length, if action_list_length == 1 { "policy" } else { "policies" }), Some(&http_transaction.id), &mut postgres_client).await;
  let response_body = ListActionResponseBody {
    actions,
    total_count: access_policy_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(action_id::get_router(state.clone()));
  return router;

}