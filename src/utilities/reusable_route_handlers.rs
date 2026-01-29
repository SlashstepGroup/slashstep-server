use std::sync::Arc;
use axum::{Extension, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyResourceType, DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT, IndividualPrincipal}, action::{Action, DEFAULT_MAXIMUM_ACTION_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, match_db_error, match_slashstepql_error, verify_user_permissions}}};

#[derive(Debug, Deserialize)]
pub struct AccessPolicyListQueryParameters {
  pub query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAccessPolicyResponseBody {
  pub access_policies: Vec<AccessPolicy>,
  pub total_count: i64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListActionsResponseBody {
  pub actions: Vec<Action>,
  pub total_count: i64
}

#[derive(Debug, Deserialize)]
pub struct ActionListQueryParameters {
  pub query: Option<String>
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

pub async fn list_actions(
  Query(query_parameters): Query<ActionListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  resource_hierarchy: ResourceHierarchy,
  action_log_entry_target_resource_type: ActionLogEntryTargetResourceType,
  action_log_entry_target_resource_id: Option<Uuid>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let list_actions_action = get_action_from_name("slashstep.actions.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &list_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  let query = query_parameters.query.unwrap_or("".to_string());
  let actions = match Action::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(actions) => actions,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_ACTION_LIST_LIMIT, "actions"),

        ResourceError::PostgresError(error) => match_db_error(&error, "actions"),

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
    reason: None, // TODO: Support reasons.
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    actor_app_id: None,
    target_resource_type: action_log_entry_target_resource_type.clone(),
    target_access_policy_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AccessPolicy { action_log_entry_target_resource_id.clone() } else { None },
    target_action_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Action { action_log_entry_target_resource_id.clone() } else { None },
    target_action_log_entry_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ActionLogEntry { action_log_entry_target_resource_id.clone() } else { None },
    target_app_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::App { action_log_entry_target_resource_id.clone() } else { None },
    target_app_authorization_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppAuthorization { action_log_entry_target_resource_id.clone() } else { None },
    target_app_authorization_credential_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppAuthorizationCredential { action_log_entry_target_resource_id.clone() } else { None },
    target_app_credential_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppCredential { action_log_entry_target_resource_id.clone() } else { None },
    target_group_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Group { action_log_entry_target_resource_id.clone() } else { None },
    target_group_membership_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::GroupMembership { action_log_entry_target_resource_id.clone() } else { None },
    target_http_transaction_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::HTTPTransaction { action_log_entry_target_resource_id.clone() } else { None },
    target_item_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Item { action_log_entry_target_resource_id.clone() } else { None },
    target_milestone_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Milestone { action_log_entry_target_resource_id.clone() } else { None }, 
    target_project_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Project { action_log_entry_target_resource_id.clone() } else { None },
    target_role_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Role { action_log_entry_target_resource_id.clone() } else { None },
    target_role_membership_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::RoleMembership { action_log_entry_target_resource_id.clone() } else { None },
    target_server_log_entry_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ServerLogEntry { action_log_entry_target_resource_id.clone() } else { None },
    target_session_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Session { action_log_entry_target_resource_id.clone() } else { None },
    target_user_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::User { action_log_entry_target_resource_id.clone() } else { None },
    target_workspace_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Workspace { action_log_entry_target_resource_id.clone() } else { None }
  }, &mut postgres_client).await.ok();
  let action_list_length = actions.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", action_list_length, if action_list_length == 1 { "action" } else { "actions" }), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let response_body = ListActionsResponseBody {
    actions,
    total_count: action_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}