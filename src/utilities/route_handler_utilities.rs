use std::{pin::Pin, sync::Arc};
use crate::{HTTPError, resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPrincipalType, ActionPermissionLevel, ResourceType}, action::Action, action_log_entry::ActionLogEntry, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, configuration::Configuration, delegation_policy::DelegationPolicy, field::Field, field_choice::FieldChoice, field_value::FieldValue, group::Group, http_transaction::HTTPTransaction, item::Item, item_connection::ItemConnection, item_connection_type::ItemConnectionType, membership::Membership, milestone::Milestone, project::Project, role::Role, server_log_entry::ServerLogEntry, session::Session, user::User, view::View, workspace::Workspace}, utilities::{slashstepql::SlashstepQLError}};
use axum::{Json, extract::rejection::JsonRejection};
use chrono::{DateTime, Utc};
use colored::Colorize;
use pg_escape::quote_literal;
use postgres::error::SqlState;
use rust_decimal::{Decimal, prelude::ToPrimitive};
use uuid::Uuid;

pub async fn get_action_log_entry_expiration_timestamp(http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Option<DateTime<Utc>>, HTTPError> {

  ServerLogEntry::trace("Getting configuration to determine whether action log entries should expire...", Some(&http_transaction.id), database_pool).await.ok();
  let should_action_log_entries_expire_configuration = match Configuration::list(&format!("name = {} LIMIT 1", quote_literal("actionLogEntries.shouldExpire")), &database_pool, None, None).await {

    Ok(configurations) => match configurations.into_iter().next() {

      Some(configuration) => configuration,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Missing configuration for actionLogEntries.shouldExpire. It may have been deleted by a user or an app. Restart the server to restore this configuration.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    }

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to retrieve configurations: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  let should_action_log_entries_expire = should_action_log_entries_expire_configuration.boolean_value.or(should_action_log_entries_expire_configuration.default_boolean_value).unwrap_or(false);
  if !should_action_log_entries_expire {

    return Ok(None);

  }

  ServerLogEntry::trace("Getting configuration to determine the expiration duration for action log entries...", Some(&http_transaction.id), database_pool).await.ok();
  let action_log_entry_expiration_duration_configuration = match Configuration::list(&format!("name = {} LIMIT 1", quote_literal("actionLogEntries.expirationDurationMilliseconds")), &database_pool, None, None).await {

    Ok(configurations) => match configurations.into_iter().next() {

      Some(configuration) => configuration,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Missing configuration for actionLogEntries.expirationDurationMilliseconds. It may have been deleted by a user or an app. Restart the server to restore this configuration.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    }

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to retrieve configurations: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_duration_milliseconds = action_log_entry_expiration_duration_configuration.number_value
    .or(action_log_entry_expiration_duration_configuration.default_number_value)
    .and_then(|decimal| decimal.to_i64());

  let expiration_timestamp = expiration_duration_milliseconds.and_then(|duration| Utc::now().checked_add_signed(chrono::Duration::milliseconds(duration)));

  return Ok(expiration_timestamp);

}

pub async fn get_json_web_token_public_key(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<String, HTTPError> {

  let json_web_token_public_key = match crate::get_json_web_token_public_key().await {

    Ok(json_web_token_public_key) => json_web_token_public_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get JSON web token public key: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(json_web_token_public_key);

}

pub async fn get_json_web_token_private_key(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<String, HTTPError> {

  let json_web_token_private_key = match crate::get_json_web_token_private_key().await {

    Ok(json_web_token_private_key) => json_web_token_private_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get JSON web token private key: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(json_web_token_private_key);

}

pub fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

pub async fn get_action_by_name(action_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

  ServerLogEntry::trace(&format!("Getting action \"{}\"...", action_name), Some(&http_transaction.id), &database_pool).await.ok();
  let action = match Action::get_by_name(&action_name, &database_pool).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"{}\": {:?}", action_name, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub enum AuthenticatedPrincipal {
  User(Arc<User>),
  App(Arc<App>)
}

pub fn is_authenticated_user_anonymous(authenticated_user: Option<&Arc<User>>) -> bool {

  return authenticated_user.and_then(|authenticated_user| Some(authenticated_user.is_anonymous)).unwrap_or(false)

}

pub async fn verify_delegate_permissions(app_authorization_id: Option<&Uuid>, action_id: &Uuid, http_transaction_id: &Uuid, required_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let app_authorization_id = match app_authorization_id {

    Some(app_authorization_id) => app_authorization_id,

    None => return Ok(())

  };

  let query = format!("action_id = {} AND delegate_app_authorization_id = {} LIMIT 1", quote_literal(&action_id.to_string()), quote_literal(&app_authorization_id.to_string()));
  let delegation_policy = match DelegationPolicy::list(&query, &database_pool, None, None).await {

    Ok(delegation_policies) => {
      
      let delegation_policy = match delegation_policies.first() {

        Some(delegation_policy) => delegation_policy.clone(),

        None => return Err(HTTPError::ForbiddenError(Some(format!("The app authorization {} does not have access to the action {}.", app_authorization_id, action_id))))

      };

      delegation_policy

    },

    Err(error) => {

      let http_error = match error {

        ResourceError::NotFoundError(_) => HTTPError::ForbiddenError(Some(format!("The app authorization {} does not have access to the action {}.", app_authorization_id, action_id))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  if delegation_policy.maximum_permission_level < *required_permission_level {

    let http_error = HTTPError::ForbiddenError(Some(format!("The app authorization {} does not have access to the action {}.", app_authorization_id, action_id)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
    return Err(http_error);

  }

  return Ok(());

}

pub async fn verify_principal_permissions(principal_type: &AccessPolicyPrincipalType, principal_id: &Uuid, is_principal_anonymous: bool, resource_type: &ResourceType, resource_id: Option<&Uuid>, action: &Action, http_transaction: &HTTPTransaction, minimum_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  ServerLogEntry::trace(&format!("Verifying principal may use \"{}\" action...", action.name), Some(&http_transaction.id), &database_pool).await.ok();

  let database_client = match database_pool.get().await {

    Ok(database_client) => database_client,

    Err(error) => {

      let http_error = map_postgres_error_to_http_error(error);
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };
  let permission_level_row = match database_client.query_one("SELECT get_principal_permission_level($1, $2, $3, $4, $5)", &[
    &principal_type,
    &principal_id,
    &resource_type,
    &resource_id,
    &action.id
  ]).await {

    Ok(permission_level_row) => permission_level_row,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to verify permissions for principal {} with ID {}: {:?}", principal_type, principal_id, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };
  let actual_permission_level: ActionPermissionLevel = permission_level_row.get(0);

  if &actual_permission_level < minimum_permission_level {

    let location = match resource_type {

      ResourceType::Server => "the server".to_string(),

      _ => format!("{} {}", resource_type.to_string().to_lowercase(), resource_id.unwrap_or(&Uuid::nil()).to_string())

    };
    let message = format!("You need at least {} permission to the \"{}\" action on {}.", minimum_permission_level.to_string(), action.name, location);
    let http_error = if is_principal_anonymous { HTTPError::UnauthorizedError(Some(message)) } else { HTTPError::ForbiddenError(Some(message)) };
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
    return Err(http_error);

  }

  return Ok(());

}

pub async fn get_access_policy_by_id(access_policy_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AccessPolicy, HTTPError> {

  let access_policy = get_resource_by_id::<AccessPolicy, _>("access policy", &access_policy_id, &http_transaction, &database_pool, |access_policy_id, database_pool| Box::new(AccessPolicy::get_by_id(access_policy_id, database_pool))).await?;
  return Ok(access_policy);

}

pub async fn get_action_by_id(action_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

  let action = get_resource_by_id::<Action, _>("action", &action_id, &http_transaction, &database_pool, |action_id, database_pool| Box::new(Action::get_by_id(action_id, database_pool))).await?;
  return Ok(action);

}

pub async fn get_action_log_entry_by_id(action_log_entry_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ActionLogEntry, HTTPError> {

  let action_log_entry = get_resource_by_id::<ActionLogEntry, _>("action log entry", &action_log_entry_id, &http_transaction, &database_pool, |action_log_entry_id, database_pool| Box::new(ActionLogEntry::get_by_id(action_log_entry_id, database_pool))).await?;
  return Ok(action_log_entry);

}

pub async fn get_app_by_id(app_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<App, HTTPError> {

  let app = get_resource_by_id::<App, _>("app", &app_id, &http_transaction, &database_pool, |app_id, database_pool| Box::new(App::get_by_id(app_id, database_pool))).await?;
  return Ok(app);

}

pub async fn get_app_authorization_by_id(app_authorization_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorization, HTTPError> {

  let app_authorization = get_resource_by_id::<AppAuthorization, _>("app authorization", &app_authorization_id, &http_transaction, &database_pool, |app_authorization_id, database_pool| Box::new(AppAuthorization::get_by_id(app_authorization_id, database_pool))).await?;
  return Ok(app_authorization);

}

pub async fn get_app_authorization_credential_by_id(app_authorization_credential_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorizationCredential, HTTPError> {

  let app_authorization_credential = get_resource_by_id::<AppAuthorizationCredential, _>("app authorization credential", &app_authorization_credential_id, &http_transaction, &database_pool, |app_authorization_credential_id, database_pool| Box::new(AppAuthorizationCredential::get_by_id(app_authorization_credential_id, database_pool))).await?;
  return Ok(app_authorization_credential);

}

pub async fn get_app_credential_by_id(app_credential_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppCredential, HTTPError> {

  let app_credential = get_resource_by_id::<AppCredential, _>("app credential", &app_credential_id, &http_transaction, &database_pool, |app_credential_id, database_pool| Box::new(AppCredential::get_by_id(app_credential_id, database_pool))).await?;
  return Ok(app_credential);

}

pub async fn get_user_by_id(user_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<User, HTTPError> {

  let user = match User::get_by_id(&user_id, database_pool).await {

    Ok(user) => user,

    Err(resource_error) => {

      let http_error = match resource_error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get user {}: {:?}", user_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(user);

}

pub async fn get_configuration_by_id(configuration_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Configuration, HTTPError> {

  let configuration = get_resource_by_id::<Configuration, _>("configuration", &configuration_id, &http_transaction, &database_pool, |configuration_id, database_pool| Box::new(Configuration::get_by_id(configuration_id, database_pool))).await?;
  return Ok(configuration);

}

pub async fn get_uuid_from_string(string: &str, resource_type_name_singular: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Uuid, HTTPError> {

  let uuid = match Uuid::parse_str(string) {

    Ok(uuid) => uuid,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some(format!("You must provide a valid UUID for the {} ID.", resource_type_name_singular)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(uuid);

}

pub async fn get_field_by_id(field_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Field, HTTPError> {

  let field = get_resource_by_id::<Field, _>("field", &field_id, &http_transaction, &database_pool, |field_id, database_pool| Box::new(Field::get_by_id(field_id, database_pool))).await?;
  return Ok(field);

}

pub async fn get_field_choice_by_id(field_choice_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<FieldChoice, HTTPError> {

  let field_choice = get_resource_by_id::<FieldChoice, _>("field choice", &field_choice_id, &http_transaction, &database_pool, |field_choice_id, database_pool| Box::new(FieldChoice::get_by_id(field_choice_id, database_pool))).await?;
  return Ok(field_choice);

}

pub async fn get_field_value_by_id(field_value_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<FieldValue, HTTPError> {

  let field_value = get_resource_by_id::<FieldValue, _>("field value", &field_value_id, &http_transaction, &database_pool, |field_value_id, database_pool| Box::new(FieldValue::get_by_id(field_value_id, database_pool))).await?;
  return Ok(field_value);

}

pub async fn get_item_by_id(item_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Item, HTTPError> {

  let item = get_resource_by_id::<Item, _>("item", &item_id, &http_transaction, &database_pool, |item_id, database_pool| Box::new(Item::get_by_id(item_id, database_pool))).await?;
  return Ok(item);

}

pub async fn get_group_by_id(group_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Group, HTTPError> {

  let group = get_resource_by_id::<Group, _>("group", &group_id, &http_transaction, &database_pool, |group_id, database_pool| Box::new(Group::get_by_id(group_id, database_pool))).await?;
  return Ok(group);

}

pub async fn get_http_transaction_by_id(http_transaction_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<HTTPTransaction, HTTPError> {

  let target_http_transaction = get_resource_by_id::<HTTPTransaction, _>("HTTP transaction", &http_transaction_id, &http_transaction, &database_pool, |http_transaction_id, database_pool| Box::new(HTTPTransaction::get_by_id(http_transaction_id, database_pool))).await?;
  return Ok(target_http_transaction);

}

pub async fn get_item_connection_by_id(item_connection_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ItemConnection, HTTPError> {

  let target_item_connection = get_resource_by_id::<ItemConnection, _>("item connection", &item_connection_id, &http_transaction, &database_pool, |item_connection_id, database_pool| Box::new(ItemConnection::get_by_id(item_connection_id, database_pool))).await?;
  return Ok(target_item_connection);

}

pub async fn get_item_connection_type_by_id(item_connection_type_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ItemConnectionType, HTTPError> {

  let target_item_connection_type = get_resource_by_id::<ItemConnectionType, _>("item connection type", &item_connection_type_id, &http_transaction, &database_pool, |item_connection_type_id, database_pool| Box::new(ItemConnectionType::get_by_id(item_connection_type_id, database_pool))).await?;
  return Ok(target_item_connection_type);

}

pub async fn get_membership_by_id(membership_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Membership, HTTPError> {

  let target_membership = get_resource_by_id::<Membership, _>("membership", &membership_id, &http_transaction, &database_pool, |membership_id, database_pool| Box::new(Membership::get_by_id(membership_id, database_pool))).await?;
  return Ok(target_membership);
  
}

pub async fn get_milestone_by_id(milestone_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Milestone, HTTPError> {

  let target_milestone = get_resource_by_id::<Milestone, _>("milestone", &milestone_id, &http_transaction, &database_pool, |milestone_id, database_pool| Box::new(Milestone::get_by_id(milestone_id, database_pool))).await?;
  return Ok(target_milestone);

}

pub async fn get_project_by_id(project_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Project, HTTPError> {

  let project = get_resource_by_id::<Project, _>("project", &project_id, &http_transaction, &database_pool, |project_id, database_pool| Box::new(Project::get_by_id(project_id, database_pool))).await?;
  return Ok(project);

}

pub async fn get_role_by_id(role_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Role, HTTPError> {

  let role = get_resource_by_id::<Role, _>("role", &role_id, &http_transaction, &database_pool, |role_id, database_pool| Box::new(Role::get_by_id(role_id, database_pool))).await?;
  return Ok(role);

}

pub async fn get_server_log_entry_by_id(server_log_entry_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ServerLogEntry, HTTPError> {

  let server_log_entry = get_resource_by_id::<ServerLogEntry, _>("server log entry", &server_log_entry_id, &http_transaction, &database_pool, |server_log_entry_id, database_pool| Box::new(ServerLogEntry::get_by_id(server_log_entry_id, database_pool))).await?;
  return Ok(server_log_entry);

}

pub async fn get_session_by_id(session_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Session, HTTPError> {

  let session = get_resource_by_id::<Session, _>("session", &session_id, &http_transaction, &database_pool, |session_id, database_pool| Box::new(Session::get_by_id(session_id, database_pool))).await?;
  return Ok(session);

}

pub async fn get_view_by_id(view_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<View, HTTPError> {

  let view = get_resource_by_id::<View, _>("view", &view_id, &http_transaction, &database_pool, |view_id, database_pool| Box::new(View::get_by_id(view_id, database_pool))).await?;
  return Ok(view);

}

pub async fn get_workspace_by_id(workspace_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Workspace, HTTPError> {

  let workspace = get_resource_by_id::<Workspace, _>("workspace", &workspace_id, &http_transaction, &database_pool, |workspace_id, database_pool| Box::new(Workspace::get_by_id(workspace_id, database_pool))).await?;
  return Ok(workspace);

}

pub async fn get_delegation_policy_by_id(delegation_policy_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<DelegationPolicy, HTTPError> {

  let delegation_policy = get_resource_by_id::<DelegationPolicy, _>("delegation policy", &delegation_policy_id, &http_transaction, &database_pool, |delegation_policy_id, database_pool| Box::new(DelegationPolicy::get_by_id(delegation_policy_id, database_pool))).await?;
  return Ok(delegation_policy);

}

pub async fn get_resource_by_id<ResourceStruct, GetResourceByIDFunction>(
  resource_type_name_singular: &str, 
  resource_id: &Uuid, 
  http_transaction: &HTTPTransaction, 
  database_pool: &deadpool_postgres::Pool, 
  get_resource_by_id_function: GetResourceByIDFunction
) -> Result<ResourceStruct, HTTPError> where
  GetResourceByIDFunction: for<'a> Fn(&'a Uuid, &'a deadpool_postgres::Pool) -> Box<dyn Future<Output = Result<ResourceStruct, ResourceError>> + 'a + Send>
{

  ServerLogEntry::trace(&format!("Getting {} {}...", resource_type_name_singular, resource_id), Some(&http_transaction.id), database_pool).await.ok();
  let resource = match Pin::from(get_resource_by_id_function(&resource_id, database_pool)).await {

    Ok(resource) => resource,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get {} {}: {:?}", resource_type_name_singular, resource_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource);

}

pub fn match_slashstepql_error(error: &SlashstepQLError, maximum_limit: &i64, resource_type_plural: &str) -> HTTPError {

  let http_error = match error {

    SlashstepQLError::SlashstepQLInvalidLimitError(error) => HTTPError::UnprocessableEntity(Some(format!("The provided limit must be zero or a positive integer of {} or less. You provided {}.", maximum_limit, error.limit_string))), // TODO: Make this configurable through resource policies.

    SlashstepQLError::InvalidFieldError(field) => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid. The field \"{}\" is not allowed.", field))),

    SlashstepQLError::InvalidQueryError(()) => HTTPError::BadRequestError(Some(format!("The provided query is invalid."))),

    _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type_plural, error)))

  };

  return http_error;

}

pub fn match_db_error(error: &postgres::Error, resource_type: &str) -> HTTPError {

  let http_error = match error.as_db_error() {

    Some(db_error) => match db_error.code() {

      &SqlState::UNDEFINED_FUNCTION => HTTPError::BadRequestError(Some(format!("The provided query is invalid."))),

      _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

    },

    None => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

  };

  return http_error;

}

pub fn get_principal_type_and_id_from_principal(user: Option<&Arc<User>>, app: Option<&Arc<App>>) -> Result<(AccessPolicyPrincipalType, Uuid), HTTPError> {

  if let Some((principal_type, principal_id)) =
    user
    .and_then(|user| Some((AccessPolicyPrincipalType::User, user.id)))
    .or_else(|| app.and_then(|app| Some((AccessPolicyPrincipalType::App, app.id)))) 
  {

    return Ok((principal_type, principal_id));

  }

  return Err(HTTPError::InternalServerError(Some("Couldn't find a user or app for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.".to_string())));

}

pub async fn get_request_body_without_json_rejection<T>(request_body: Result<Json<T>, JsonRejection>, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Json<T>, HTTPError> {

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &database_pool).await.ok();
  let request_body = match request_body {

    Ok(updated_access_policy_properties) => updated_access_policy_properties,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(request_body);

}

pub async fn get_configuration_by_name(configuration_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Configuration, HTTPError> {

  ServerLogEntry::trace(&format!("Getting configuration \"{}\"...", configuration_name), Some(&http_transaction.id), &database_pool).await.ok();
  let configuration = match Configuration::get_by_name(&configuration_name, &database_pool).await {

    Ok(configuration) => configuration,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(_) => HTTPError::InternalServerError(Some(format!("Missing configuration for {}. It may have been deleted by a user or an app. Try restarting the server to restore this configuration.", configuration_name))),

        error => HTTPError::InternalServerError(Some(format!("Failed to get configuration \"{}\": {:?}", configuration_name, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(configuration);

}

pub async fn validate_field_length(name: &str, configuration_name: &str, field_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let maximum_name_length_configuration = get_configuration_by_name(configuration_name, http_transaction, database_pool).await?;
  let maximum_name_length = match maximum_name_length_configuration.number_value.or(maximum_name_length_configuration.default_number_value) {

    Some(maximum_name_length) => match maximum_name_length.to_usize() {

      Some(maximum_name_length) => maximum_name_length,

      None => {

        let http_error = HTTPError::InternalServerError(Some(format!("Invalid number value for configuration {}. The value must be a positive integer that can be represented as a usize.", configuration_name)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
        return Err(http_error);

      }

    },

    None => {

      ServerLogEntry::warning(&format!("Missing value and default value for configuration {}. This is a security risk. Consider setting a restrictive maximum name length in the configuration.", configuration_name), Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace(&format!("Validating \"{}\" field length...", field_name), Some(&http_transaction.id), database_pool).await.ok();
  if name.len() > maximum_name_length {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("The \"{}\" field must be at most {} characters long.", field_name, maximum_name_length)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }
  

  Ok(())

}

pub async fn validate_resource_name(name: &str, configuration_name: &str, resource_type_name_singular: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let allowed_name_regex_configuration = get_configuration_by_name(configuration_name, http_transaction, database_pool).await?;
  let allowed_name_regex_string = match allowed_name_regex_configuration.text_value.or(allowed_name_regex_configuration.default_text_value) {

    Some(allowed_name_regex_string) => allowed_name_regex_string,

    None => {

      ServerLogEntry::warning(&format!("Missing value and default value for configuration {}. Consider setting a regex pattern in the configuration for better security.", configuration_name), Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace(&format!("Creating regex for validating {} names...", resource_type_name_singular.to_lowercase()), Some(&http_transaction.id), database_pool).await.ok();
  let regex = match regex::Regex::new(&allowed_name_regex_string) {

    Ok(regex) => regex,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create regex for validating {} names: {:?}", resource_type_name_singular.to_lowercase(), error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
      return Err(http_error)

    }

  };

  ServerLogEntry::trace(&format!("Validating {} name against regex...", resource_type_name_singular.to_lowercase()), Some(&http_transaction.id), database_pool).await.ok();
  if !regex.is_match(name) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("{} names must match the allowed pattern: {}", resource_type_name_singular, allowed_name_regex_string)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  Ok(())

}

pub async fn validate_resource_display_name(name: &str, configuration_name: &str, resource_type_name_singular: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let allowed_display_name_regex_configuration = get_configuration_by_name(configuration_name, http_transaction, database_pool).await?;
  let allowed_display_name_regex_string = match allowed_display_name_regex_configuration.text_value.or(allowed_display_name_regex_configuration.default_text_value) {

    Some(allowed_display_name_regex_string) => allowed_display_name_regex_string,

    None => {

      ServerLogEntry::warning(&format!("Missing value and default value for configuration {}. Consider setting a regex pattern in the configuration for better security.", configuration_name), Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace(&format!("Creating regex for validating {} display names...", resource_type_name_singular.to_lowercase()), Some(&http_transaction.id), database_pool).await.ok();
  let regex = match regex::Regex::new(&allowed_display_name_regex_string) {

    Ok(regex) => regex,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create regex for validating {} display names: {:?}", resource_type_name_singular.to_lowercase(), error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
      return Err(http_error)

    }

  };

  ServerLogEntry::trace(&format!("Validating {} display name against regex...", resource_type_name_singular.to_lowercase()), Some(&http_transaction.id), database_pool).await.ok();
  if !regex.is_match(name) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("{} display names must match the allowed pattern: {}", resource_type_name_singular, allowed_display_name_regex_string)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  Ok(())

}

pub async fn validate_decimal_is_within_range(decimal: &Decimal, minimum_configuration_name: &str, maximum_configuration_name: &str, field_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let minimum_configuration = get_configuration_by_name(minimum_configuration_name, http_transaction, database_pool).await?;
  let minimum = match minimum_configuration.number_value.or(minimum_configuration.default_number_value) {

    Some(minimum) => Some(minimum),

    None => {

      ServerLogEntry::warning(&format!("Missing value and default value for configuration {}. This is a security risk. Consider setting a minimum value in the configuration for better validation.", minimum_configuration_name), Some(&http_transaction.id), database_pool).await.ok();
      None

    }

  };

  if minimum.and_then(|minimum| Some(decimal < &minimum)).unwrap_or(false) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("The \"{}\" must be at least {}.", field_name, minimum.unwrap())));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  let maximum_configuration = get_configuration_by_name(maximum_configuration_name, http_transaction, database_pool).await?;
  let maximum = match maximum_configuration.number_value.or(maximum_configuration.default_number_value) {

    Some(maximum) => Some(maximum),

    None => {

      ServerLogEntry::warning(&format!("Missing value and default value for configuration {}. This is a security risk. Consider setting a maximum value in the configuration for better validation.", maximum_configuration_name), Some(&http_transaction.id), database_pool).await.ok();
      None

    }

  };

  if maximum.and_then(|maximum| Some(decimal > &maximum)).unwrap_or(false) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("The \"{}\" must be at most {}.", field_name, maximum.unwrap())));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  Ok(())

}