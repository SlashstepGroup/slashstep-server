use std::sync::Arc;

use crate::{HTTPError, resources::{DeletableResource, ResourceError, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, IndividualPrincipal, Principal, ResourceHierarchy}, action::Action, app::App, app_authorization::AppAuthorization, app_credential::AppCredential, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}, resource_hierarchy::{self, ResourceHierarchyError}, slashstepql::SlashstepQLError}};
use colored::Colorize;
use postgres::error::SqlState;
use uuid::Uuid;

pub fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

pub async fn get_action_from_name(action_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

  ServerLogEntry::trace(&format!("Getting action \"{}\"...", action_name), Some(&http_transaction.id), &database_pool).await.ok();
  let action = match Action::get_by_name(&action_name, &database_pool).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"{}\": {:?}", action_name, error)));
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub enum AuthenticatedPrincipal {
  User(Arc<User>),
  App(Arc<App>)
}

pub async fn verify_principal_permissions(authenticated_principal: &AuthenticatedPrincipal, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &AccessPolicyPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

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

pub async fn get_action_from_id(action_id_string: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

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
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_app_authorization_from_id(app_authorization_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorization, HTTPError> {

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
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_authorization);

}

pub async fn get_app_credential_from_id(app_credential_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppCredential, HTTPError> {

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
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_credential);

}

pub async fn get_app_from_id(app_id_string: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<App, HTTPError> {

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
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app);

}

pub async fn get_resource_hierarchy<T: DeletableResource>(deletable_resource: &T, resource_type: &AccessPolicyResourceType, resource_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ResourceHierarchy, HTTPError> {

  let resource_type_string = resource_type.to_string().to_lowercase();
  ServerLogEntry::trace(&format!("Getting resource hierarchy for {} {}...", resource_type_string, resource_id), Some(&http_transaction.id), &database_pool).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&resource_type, &Some(*resource_id), &database_pool).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {

        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned {} {}...", resource_type_string, resource_id), Some(&http_transaction.id), &database_pool).await.ok();

          let http_error = match deletable_resource.delete(&database_pool).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned {}: {:?}", resource_type_string, error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
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

    SlashstepQLError::InvalidQueryError(()) => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid."))),

    _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

  };

  return http_error;

}

pub fn match_db_error(error: &postgres::Error, resource_type: &str) -> HTTPError {

  let http_error = match error.as_db_error() {

    Some(db_error) => match db_error.code() {

      &SqlState::UNDEFINED_FUNCTION => HTTPError::UnprocessableEntity(Some(format!("The provided query is invalid."))),

      _ => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

    },

    None => HTTPError::InternalServerError(Some(format!("Failed to list {}: {:?}", resource_type, error)))

  };

  return http_error;

}

pub fn get_authenticated_principal(user: &Option<Arc<User>>, app: &Option<Arc<App>>) -> Result<AuthenticatedPrincipal, HTTPError> {

  if let Some(authenticated_principal) =
    user.clone()
    .and_then(|user| Some(AuthenticatedPrincipal::User(user)))
    .or_else(|| app.clone().and_then(|app| Some(AuthenticatedPrincipal::App(app)))) 
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