use std::sync::Arc;

use crate::{HTTPError, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, Principal, ResourceHierarchy}, action::{Action, ActionError}, action_log_entry::ActionLogEntry, app::{App, AppError}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}, resource_hierarchy::{self, ResourceHierarchyError}, slashstepql::SlashstepQLError}};
use colored::Colorize;
use postgres::error::SqlState;
use uuid::Uuid;

pub fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

pub async fn get_action_from_name(action_name: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  ServerLogEntry::trace(&format!("Getting action \"{}\"...", action_name), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let action = match Action::get_by_name(&action_name, &mut postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"{}\": {:?}", action_name, error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_user_from_option_user(user: &Option<Arc<User>>, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Arc<User>, HTTPError> {

  let Some(user) = user else {

    let http_error = HTTPError::InternalServerError(Some(format!("Couldn't find a user for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.")));
    http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
    return Err(http_error);

  };

  return Ok(user.clone());

}

pub async fn verify_user_permissions(user: &User, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &AccessPolicyPermissionLevel, mut postgres_client: &mut deadpool_postgres::Client) -> Result<(), HTTPError> {

  ServerLogEntry::trace(&format!("Verifying principal may use \"{}\" action...", action.name), Some(&http_transaction.id), &mut postgres_client).await.ok();

  match PrincipalPermissionVerifier::verify_permissions(&Principal::User(user.id), &action.id, &resource_hierarchy, &minimum_permission_level, &mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = match error {

        PrincipalPermissionVerifierError::ForbiddenError { .. } => {
          
          let message = format!("You need at least {} permission to the \"{}\" action.", minimum_permission_level.to_string(), action.name);
          if user.is_anonymous {

            HTTPError::UnauthorizedError(Some(message))

          } else {

            HTTPError::ForbiddenError(Some(message))
          
          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  }

  return Ok(());

}

pub async fn get_action_from_id(action_id_string: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  let action_id = match Uuid::parse_str(&action_id_string) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting action {}...", action_id), Some(&http_transaction.id), postgres_client).await.ok();
  let action = match Action::get_by_id(&action_id, postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = match error {
        
        ActionError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)))

      };
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_app_from_id(app_id_string: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<App, HTTPError> {

  let app_id = match Uuid::parse_str(&app_id_string) {

    Ok(app_id) => app_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting app {}...", app_id), Some(&http_transaction.id), postgres_client).await.ok();
  let app = match App::get_by_id(&app_id, postgres_client).await {

    Ok(app) => app,

    Err(error) => {

      let http_error = match error {
        
        AppError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get app {}: {:?}", app_id, error)))

      };
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app);

}

pub async fn get_resource_hierarchy_for_app(app: &App, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  ServerLogEntry::trace(&format!("Getting resource hierarchy for app {}...", app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&AccessPolicyResourceType::App, &Some(app.id), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {

        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned app {}...", app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

          let http_error = match app.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned app: {:?}", error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
          return Err(http_error);

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

pub async fn get_resource_hierarchy_for_action(action: &Action, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  ServerLogEntry::trace(&format!("Getting resource hierarchy for action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&AccessPolicyResourceType::Action, &Some(action.id), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {

        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

          let http_error = match action.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned action: {:?}", error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
          return Err(http_error);

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

pub async fn get_resource_hierarchy_for_action_log_entry(action_log_entry: &ActionLogEntry, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  ServerLogEntry::trace(&format!("Getting resource hierarchy for action log entry {}...", action_log_entry.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&AccessPolicyResourceType::ActionLogEntry, &Some(action_log_entry.id), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {

        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned action log entry {}...", action_log_entry.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
          let http_error = match action_log_entry.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned action log entry: {:?}", error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
          return Err(http_error);

        },
        
        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
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