use std::{pin::Pin, sync::Arc};

use crate::{HTTPError, resources::{DeletableResource, ResourceError, access_policy::{AccessPolicyResourceType, ActionPermissionLevel, IndividualPrincipal, Principal, ResourceHierarchy}, action::Action, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, field_value::FieldValue, delegation_policy::DelegationPolicy, field::Field, field_choice::FieldChoice, http_transaction::HTTPTransaction, item::Item, project::Project, server_log_entry::ServerLogEntry, user::User}, utilities::{principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}, resource_hierarchy::{self, ResourceHierarchyError}, slashstepql::SlashstepQLError}};
use colored::Colorize;
use pg_escape::quote_literal;
use postgres::error::SqlState;
use uuid::Uuid;

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

pub async fn verify_delegate_permissions(app_authorization_id: Option<&Uuid>, action_id: &Uuid, http_transaction_id: &Uuid, required_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let app_authorization_id = match app_authorization_id {

    Some(app_authorization_id) => app_authorization_id,

    None => return Ok(())

  };

  let query = format!("action_id = {} AND delegate_app_authorization_id = {} LIMIT 1", quote_literal(&action_id.to_string()), quote_literal(&app_authorization_id.to_string()));
  let delegation_policy = match DelegationPolicy::list(&query, &database_pool, None).await {

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

pub async fn verify_principal_permissions(authenticated_principal: &AuthenticatedPrincipal, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  ServerLogEntry::trace(&format!("Verifying principal may use \"{}\" action...", action.name), Some(&http_transaction.id), &database_pool).await.ok();

  let principal = match authenticated_principal {
    AuthenticatedPrincipal::User(user) => Principal::User(user.id),
    AuthenticatedPrincipal::App(app) => Principal::App(app.id)
  };

  match PrincipalPermissionVerifier::verify_permissions(&principal, &action.id, &resource_hierarchy, &minimum_permission_level, &database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = match error {

        PrincipalPermissionVerifierError::ForbiddenError { .. } => {
          
          let message = format!("You need at least {} permission to the \"{}\" action.", minimum_permission_level.to_string(), action.name);
          match authenticated_principal {
            AuthenticatedPrincipal::User(user) => if user.is_anonymous { HTTPError::UnauthorizedError(Some(message)) } else { HTTPError::ForbiddenError(Some(message)) },
            AuthenticatedPrincipal::App(_) => HTTPError::ForbiddenError(Some(message))
          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  }

  return Ok(());

}

pub async fn get_action_by_id(action_id_string: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

  let action_id = match Uuid::parse_str(&action_id_string) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting action {}...", action_id), Some(&http_transaction.id), database_pool).await.ok();
  let action = match Action::get_by_id(&action_id, database_pool).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_user_by_id(user_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<User, HTTPError> {

  let user_id = match Uuid::parse_str(&user_id) {

    Ok(user_id) => user_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

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

pub async fn get_app_authorization_by_id(app_authorization_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorization, HTTPError> {

  let app_authorization_id = match Uuid::parse_str(&app_authorization_id) {

    Ok(app_authorization_id) => app_authorization_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the app ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting app authorization {}...", app_authorization_id), Some(&http_transaction.id), database_pool).await.ok();
  let app_authorization = match AppAuthorization::get_by_id(&app_authorization_id, database_pool).await {

    Ok(app_authorization) => app_authorization,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get app authorization {}: {:?}", app_authorization_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_authorization);

}

pub async fn get_app_credential_by_id(app_credential_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppCredential, HTTPError> {

  let app_credential_id = match Uuid::parse_str(&app_credential_id) {

    Ok(app_credential_id) => app_credential_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the app ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting app credential {}...", app_credential_id), Some(&http_transaction.id), database_pool).await.ok();
  let app_credential = match AppCredential::get_by_id(&app_credential_id, database_pool).await {

    Ok(app_credential) => app_credential,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get app credential {}: {:?}", app_credential_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_credential);

}

pub async fn get_app_by_id(app_id_string: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<App, HTTPError> {

  let app_id = match Uuid::parse_str(&app_id_string) {

    Ok(app_id) => app_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the app ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting app {}...", app_id), Some(&http_transaction.id), database_pool).await.ok();
  let app = match App::get_by_id(&app_id, database_pool).await {

    Ok(app) => app,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get app {}: {:?}", app_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app);

}

pub async fn get_app_authorization_credential_by_id(app_authorization_credential_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorizationCredential, HTTPError> {

  let app_authorization_credential_id = match Uuid::parse_str(&app_authorization_credential_id) {

    Ok(app_authorization_credential_id) => app_authorization_credential_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the app authorization credential ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting app authorization credential {}...", app_authorization_credential_id), Some(&http_transaction.id), database_pool).await.ok();
  let app_authorization_credential = match AppAuthorizationCredential::get_by_id(&app_authorization_credential_id, database_pool).await {

    Ok(app_authorization_credential) => app_authorization_credential,

    Err(error) => {

      let http_error = match error {
        
        ResourceError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get app authorization credential {}: {:?}", app_authorization_credential_id, error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_authorization_credential);

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

pub async fn get_project_by_id(project_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Project, HTTPError> {

  let project = get_resource_by_id::<Project, _>("project", &project_id, &http_transaction, &database_pool, |project_id, database_pool| Box::new(Project::get_by_id(project_id, database_pool))).await?;
  return Ok(project);

}

pub async fn get_item_by_id(item_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Item, HTTPError> {

  let item = get_resource_by_id::<Item, _>("item", &item_id, &http_transaction, &database_pool, |item_id, database_pool| Box::new(Item::get_by_id(item_id, database_pool))).await?;
  return Ok(item);

}

pub async fn get_resource_by_id<ResourceStruct, GetResourceByIDFunction>(
  resource_type_name_singular: &str, 
  resource_id: &Uuid, 
  http_transaction: &HTTPTransaction, 
  database_pool: &deadpool_postgres::Pool, 
  get_resource_by_id_function: GetResourceByIDFunction
) -> Result<ResourceStruct, HTTPError> where 
  ResourceStruct: DeletableResource,
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

pub async fn get_resource_hierarchy<T: DeletableResource>(deletable_resource: &T, resource_type: &AccessPolicyResourceType, resource_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ResourceHierarchy, HTTPError> {

  let resource_type_string = resource_type.to_string().to_lowercase();
  ServerLogEntry::trace(&format!("Getting resource hierarchy for {} {}...", resource_type_string, resource_id), Some(&http_transaction.id), &database_pool).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&resource_type, Some(resource_id), &database_pool).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {

        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned {} {}...", resource_type_string, resource_id), Some(&http_transaction.id), &database_pool).await.ok();

          let http_error = match deletable_resource.delete(&database_pool).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned {}: {:?}", resource_type_string, error)))

          };
          
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
          return Err(http_error);

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

pub fn match_slashstepql_error(error: &SlashstepQLError, maximum_limit: &i64, resource_type: &str) -> HTTPError {

  let http_error = match error {

    SlashstepQLError::SlashstepQLInvalidLimitError(error) => HTTPError::UnprocessableEntity(Some(format!("The provided limit must be zero or a positive integer of {} or less. You provided {}.", maximum_limit, error.limit_string))), // TODO: Make this configurable through resource policies.

    SlashstepQLError::InvalidFieldError(field) => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid. The field \"{}\" is not allowed.", field))),

    SlashstepQLError::InvalidQueryError(()) => HTTPError::BadRequestError(Some(format!("The provided query is invalid."))),

    _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

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

pub fn get_authenticated_principal(user: Option<&Arc<User>>, app: Option<&Arc<App>>) -> Result<AuthenticatedPrincipal, HTTPError> {

  if let Some(authenticated_principal) =
    user
    .and_then(|user| Some(AuthenticatedPrincipal::User(user.clone())))
    .or_else(|| app.and_then(|app| Some(AuthenticatedPrincipal::App(app.clone())))) 
  {

    return Ok(authenticated_principal);

  }

  return Err(HTTPError::InternalServerError(Some("Couldn't find a user or app for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.".to_string())));

}

pub fn get_individual_principal_from_authenticated_principal(authenticated_principal: &AuthenticatedPrincipal) -> IndividualPrincipal {

  match authenticated_principal {
    AuthenticatedPrincipal::User(user) => IndividualPrincipal::User(user.id),
    AuthenticatedPrincipal::App(app) => IndividualPrincipal::App(app.id)
  }

}