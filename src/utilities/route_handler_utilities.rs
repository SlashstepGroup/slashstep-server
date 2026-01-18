use std::sync::Arc;

use crate::{HTTPError, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, Principal, ResourceHierarchy}, action::{Action, ActionError}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}, resource_hierarchy::{self, ResourceHierarchyError}}};
use colored::Colorize;
use uuid::Uuid;

pub fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

pub async fn get_action_from_name(action_name: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting action \"{}\"...", action_name), Some(&http_transaction.id), &mut postgres_client).await;
  let action = match Action::get_by_name(&action_name, &mut postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"{}\": {:?}", action_name, error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_user_from_option_user(user: &Option<Arc<User>>, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Arc<User>, HTTPError> {

  let Some(user) = user else {

    let http_error = HTTPError::InternalServerError(Some(format!("Couldn't find a user for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.")));
    let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
    return Err(http_error);

  };

  return Ok(user.clone());

}

pub async fn verify_user_permissions(user: &User, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &AccessPolicyPermissionLevel, mut postgres_client: &mut deadpool_postgres::Client) -> Result<(), HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Verifying principal may use \"{}\" action...", action.name), Some(&http_transaction.id), &mut postgres_client).await;

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
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
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
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Getting action {}...", action_id), Some(&http_transaction.id), postgres_client).await;
  let action = match Action::get_by_id(&action_id, postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = match error {
        
        ActionError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)))

      };
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_resource_hierarchy_for_action(action: &Action, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting resource hierarchy for action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await;
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&AccessPolicyResourceType ::Action, &Some(action.id), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          let _ = ServerLogEntry::trace(&format!("Deleting orphaned action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await;
          let http_error = match action.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned action: {:?}", error)))

          };
          
          let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
          return Err(http_error);

        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}