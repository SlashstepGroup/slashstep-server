use std::{pin::Pin, sync::Arc};
use axum::{Extension, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, resources::{DeletableResource, ResourceError, access_policy::{AccessPolicyResourceType, ActionPermissionLevel, IndividualPrincipal}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_authenticated_principal, get_individual_principal_from_authenticated_principal, get_resource_by_id, get_resource_hierarchy, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}}};

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
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
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
  let list_resources_action = get_action_by_name(list_resources_action_name, &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &list_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
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

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting {}...", resource_type_name_plural), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Pin::from(count_resources(&query, &state.database_pool, Some(&individual_principal))).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count {}: {:?}", resource_type_name_plural, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
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
    target_oauth_authorization_id: if action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::OAuthAuthorization { action_log_entry_target_resource_id.clone() } else { None },
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

pub async fn delete_resource<ResourceStruct, GetResourceByIDFunction>(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  resource_type: Option<&AccessPolicyResourceType>,
  resource_id: &Uuid,
  delete_resources_action_name: &str,
  resource_type_name_singular: &str,
  action_log_entry_target_resource_type: &ActionLogEntryTargetResourceType,
  get_resource_by_id_function: GetResourceByIDFunction
) -> Result<StatusCode, HTTPError> where
  ResourceStruct: DeletableResource,
  GetResourceByIDFunction: for<'a> Fn(&'a Uuid, &'a deadpool_postgres::Pool) -> Box<dyn Future<Output = Result<ResourceStruct, ResourceError>> + 'a + Send>
{

  let http_transaction = http_transaction.clone();
  let target_resource = get_resource_by_id::<ResourceStruct, GetResourceByIDFunction>(&resource_type_name_singular, &resource_id, &http_transaction, &state.database_pool, get_resource_by_id_function).await?;
  let resource_hierarchy = match resource_type {
    
    Some(resource_type) => get_resource_hierarchy(&target_resource, &resource_type, &resource_id, &http_transaction, &state.database_pool).await?,

    // Access policies currently lack a resource hierarchy, so we'll just return the server.
    None => vec![(AccessPolicyResourceType::Server, None)]

  };
  let delete_resources_action = get_action_by_name(&delete_resources_action_name, &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &delete_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  match target_resource.delete(&state.database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete {}: {:?}", resource_type_name_singular, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    reason: None, // TODO: Support reasons.
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: action_log_entry_target_resource_type.clone(),
    target_access_policy_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AccessPolicy { Some(resource_id.clone()) } else { None },
    target_action_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Action { Some(resource_id.clone()) } else { None },
    target_action_log_entry_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ActionLogEntry { Some(resource_id.clone()) } else { None },
    target_app_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::App { Some(resource_id.clone()) } else { None },
    target_app_authorization_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppAuthorization { Some(resource_id.clone()) } else { None },
    target_app_authorization_credential_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppAuthorizationCredential { Some(resource_id.clone()) } else { None },
    target_app_credential_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::AppCredential { Some(resource_id.clone()) } else { None },
    target_group_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Group { Some(resource_id.clone()) } else { None },
    target_group_membership_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::GroupMembership { Some(resource_id.clone()) } else { None },
    target_http_transaction_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::HTTPTransaction { Some(resource_id.clone()) } else { None },
    target_item_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Item { Some(resource_id.clone()) } else { None },
    target_milestone_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Milestone { Some(resource_id.clone()) } else { None }, 
    target_oauth_authorization_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::OAuthAuthorization { Some(resource_id.clone()) } else { None },
    target_project_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Project { Some(resource_id.clone()) } else { None },
    target_role_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Role { Some(resource_id.clone()) } else { None },
    target_role_membership_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::RoleMembership { Some(resource_id.clone()) } else { None },
    target_server_log_entry_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ServerLogEntry { Some(resource_id.clone()) } else { None },
    target_session_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Session { Some(resource_id.clone()) } else { None },
    target_user_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::User { Some(resource_id.clone()) } else { None },
    target_workspace_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Workspace { Some(resource_id.clone()) } else { None }
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted {} {}.", resource_type_name_singular, resource_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}