use std::sync::Arc;

use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use uuid::Uuid;
use colored::Colorize;

use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyError, AccessPolicyPermissionLevel, EditableAccessPolicyProperties, Principal, ResourceHierarchy}, action::Action, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}};

fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

async fn get_user_from_option_user(user: &Option<Arc<User>>, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Arc<User>, HTTPError> {

  let Some(user) = user else {

    let http_error = HTTPError::InternalServerError(Some(format!("Couldn't find a user for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.")));
    let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
    return Err(http_error);

  };

  return Ok(user.clone());

}

async fn get_resource_hierarchy(access_policy: &AccessPolicy, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting resource hierarchy for access policy {}...", access_policy.id), Some(&http_transaction.id), &mut postgres_client).await;
  let resource_hierarchy = match access_policy.get_hierarchy(&mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          let _ = ServerLogEntry::trace(&format!("Deleting orphaned access policy {}...", access_policy.id), Some(&http_transaction.id), &mut postgres_client).await;
          let http_error = match access_policy.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned access policy: {:?}", error)))

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

async fn get_access_policy(access_policy_id: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<AccessPolicy, HTTPError> {

  let access_policy_id = match Uuid::parse_str(&access_policy_id) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Getting access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;
  
  let access_policy = match AccessPolicy::get_by_id(&access_policy_id, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),
        AccessPolicyError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        }
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;

      return Err(http_error);

    }

  };

  return Ok(access_policy);

}

async fn get_action_from_name(action_name: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

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

async fn get_action_from_id(action_id: &Uuid, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting action {}", action_id), Some(&http_transaction.id), postgres_client).await;
  let action = match Action::get_by_id(action_id, postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(action);

}

async fn verify_user_permissions(user: &User, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &AccessPolicyPermissionLevel, mut postgres_client: &mut deadpool_postgres::Client) -> Result<(), HTTPError> {

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

#[axum::debug_handler]
async fn handle_get_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let action = get_action_from_name("slashstep.accessPolicies.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  let _ = ServerLogEntry::success(&format!("Successfully returned access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(access_policy));

}


#[axum::debug_handler]
async fn handle_patch_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<EditableAccessPolicyProperties>, JsonRejection>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  let _ = ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await;
  let updated_access_policy_properties = match body {

    Ok(updated_access_policy_properties) => updated_access_policy_properties,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.accessPolicies.update", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::Editor, &mut postgres_client).await?;

  let _ = ServerLogEntry::trace(&format!("Updating access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;
  let access_policy = match access_policy.update(&updated_access_policy_properties, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update access policy: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::success(&format!("Successfully updated access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(access_policy));

}

#[axum::debug_handler]
async fn handle_delete_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let delete_access_policy_action = get_action_from_name("slashstep.accessPolicies.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::Editor, &mut postgres_client).await?;

  match access_policy.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete access policy: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  }

  let _ = ServerLogEntry::success(&format!("Successfully deleted access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies/{access_policy_id}", axum::routing::get(handle_get_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::patch(handle_patch_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::delete(handle_delete_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;