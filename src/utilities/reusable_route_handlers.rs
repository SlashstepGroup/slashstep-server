use std::sync::Arc;
use axum::{Extension, extract::State};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, HTTPError, resources::{DeletableResource, ResourceError, access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_all_resource_hierarchies, get_authenticated_principal, get_resource_by_id, get_resource_hierarchy, verify_delegate_permissions, verify_principal_permissions}};

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

  let target_resource = get_resource_by_id::<ResourceStruct, GetResourceByIDFunction>(&resource_type_name_singular, &resource_id, &http_transaction, &state.database_pool, get_resource_by_id_function).await?;
  let resource_hierarchies = match resource_type {
    
    Some(AccessPolicyResourceType::ItemConnection) => get_all_resource_hierarchies(&target_resource, &AccessPolicyResourceType::ItemConnection, &resource_id, &http_transaction, &state.database_pool).await?,

    Some(resource_type) => match get_resource_hierarchy(&target_resource, &resource_type, &resource_id, &http_transaction, &state.database_pool).await {

      Ok(resource_hierarchy) => vec![resource_hierarchy],

      Err(error) => return Err(error)

    } 

    // Access policies currently lack a resource hierarchy, so we'll just return the server.
    None => vec![vec![(AccessPolicyResourceType::Server, None)]],

  };
  let delete_resources_action = get_action_by_name(&delete_resources_action_name, &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  for index in 0..resource_hierarchies.len() {

    let resource_hierarchy = &resource_hierarchies[index];
    match verify_principal_permissions(&authenticated_principal, &delete_resources_action, resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await {

      Ok(_) => break,

      Err(error) => {

        if index < resource_hierarchies.len() - 1 {

          continue;

        }

        return Err(error);

      }

    }

  }

  match target_resource.delete(&state.database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete {}: {:?}", resource_type_name_singular, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
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
    target_configuration_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Configuration { Some(resource_id.clone()) } else { None },
    target_delegation_policy_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::DelegationPolicy { Some(resource_id.clone()) } else { None },
    target_field_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Field { Some(resource_id.clone()) } else { None },
    target_field_choice_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::FieldChoice { Some(resource_id.clone()) } else { None },
    target_field_value_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::FieldValue { Some(resource_id.clone()) } else { None },
    target_group_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Group { Some(resource_id.clone()) } else { None },
    target_http_transaction_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::HTTPTransaction { Some(resource_id.clone()) } else { None },
    target_item_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Item { Some(resource_id.clone()) } else { None },
    target_item_connection_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ItemConnection { Some(resource_id.clone()) } else { None },
    target_item_connection_type_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ItemConnectionType { Some(resource_id.clone()) } else { None },
    target_membership_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Membership { Some(resource_id.clone()) } else { None },
    target_membership_invitation_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::MembershipInvitation { Some(resource_id.clone()) } else { None },
    target_milestone_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Milestone { Some(resource_id.clone()) } else { None }, 
    target_oauth_authorization_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::OAuthAuthorization { Some(resource_id.clone()) } else { None },
    target_project_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Project { Some(resource_id.clone()) } else { None },
    target_role_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Role { Some(resource_id.clone()) } else { None },
    target_server_log_entry_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::ServerLogEntry { Some(resource_id.clone()) } else { None },
    target_session_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Session { Some(resource_id.clone()) } else { None },
    target_user_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::User { Some(resource_id.clone()) } else { None },
    target_view_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::View { Some(resource_id.clone()) } else { None },
    target_workspace_id: if *action_log_entry_target_resource_type == ActionLogEntryTargetResourceType::Workspace { Some(resource_id.clone()) } else { None }
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted {} {}.", resource_type_name_singular, resource_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}