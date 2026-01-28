use std::sync::Arc;
use axum::{Extension, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyResourceType, DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT, IndividualPrincipal}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, match_db_error, match_slashstepql_error, verify_user_permissions}}};

#[derive(Debug, Deserialize)]
pub struct AccessPolicyListQueryParameters {
  pub query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAccessPolicyResponseBody {
  pub access_policies: Vec<AccessPolicy>,
  pub total_count: i64
}

pub async fn list_access_policies(
  Query(query_parameters): Query<AccessPolicyListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let list_access_policies_action = get_action_from_name("slashstep.accessPolicies.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  verify_user_permissions(&user, &list_access_policies_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  let query = query_parameters.query.unwrap_or("".to_string());
  let access_policies = match AccessPolicy::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(access_policies) => access_policies,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT, "access policies"),

        ResourceError::PostgresError(error) => match_db_error(&error, "access policies"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list access policies: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting access policies..."), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let access_policy_count = match AccessPolicy::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(access_policy_count) => access_policy_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count access policies: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  // TODO: Use the calling function's resource type and ID instead of referencing the instance.
  // This'll make the log more useful.
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_access_policies_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully {} returned access policies.", access_policies.len()), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let response_body = ListAccessPolicyResponseBody {
    access_policies,
    total_count: access_policy_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}