use std::{pin::Pin, sync::Arc};
use axum::{Extension, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, resources::{ResourceError, access_policy::{AccessPolicyPermissionLevel, IndividualPrincipal}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_authenticated_principal, get_individual_principal_from_authenticated_principal, match_db_error, match_slashstepql_error, verify_principal_permissions}}};

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResourcesResponseBody<ResourceStruct> {
  pub resources: Vec<ResourceStruct>,
  pub total_count: i64
}

#[derive(Debug, Deserialize)]
pub struct ResourceListQueryParameters {
  pub query: Option<String>
}

pub async fn list_resources<ResourceType: Serialize, CountResourcesFunction, ListResourcesFunction>(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  resource_hierarchy: ResourceHierarchy,
  action_log_entry_target_resource_type: ActionLogEntryTargetResourceType,
  action_log_entry_target_resource_id: Option<Uuid>,
  count_resources: CountResourcesFunction,
  list_resources: ListResourcesFunction,
  list_resources_action_name: &str,
  default_list_limit: i64,
  resource_type_name_plural: &str,
  resource_type_name_singular: &str
) -> Result<ErasedJson, HTTPError> where 
  CountResourcesFunction: for<'a> Fn(&'a str, &'a deadpool_postgres::Pool, Option<&'a IndividualPrincipal>) -> Box<dyn Future<Output = Result<i64, ResourceError>> + 'a + Send>,
  ListResourcesFunction: for<'a> Fn(&'a str, &'a deadpool_postgres::Pool, Option<&'a IndividualPrincipal>) -> Box<dyn Future<Output = Result<Vec<ResourceType>, ResourceError>> + 'a + Send>
{

  let http_transaction = http_transaction.clone();
  let list_resources_action = get_action_from_name(list_resources_action_name, &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &list_resources_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);
  let query = query_parameters.query.unwrap_or("".to_string());
  let resources = match Pin::from(list_resources(&query, &state.database_pool, Some(&individual_principal))).await {

    Ok(app_authorization_credentials) => app_authorization_credentials,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &default_list_limit, &resource_type_name_singular),

        ResourceError::PostgresError(error) => match_db_error(&error, &resource_type_name_plural),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type_name_plural, error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting {}...", resource_type_name_plural), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Pin::from(count_resources(&query, &state.database_pool, Some(&individual_principal))).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count {}: {:?}", resource_type_name_plural, error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    reason: None, // TODO: Support reasons.
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
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
  }, &state.database_pool).await.ok();
  let resource_list_length = resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", resource_list_length, if resource_list_length == 1 { resource_type_name_singular } else { resource_type_name_plural }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<ResourceType> {
    resources,
    total_count: resource_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}
