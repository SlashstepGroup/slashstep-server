use std::sync::Arc;

use axum::{Extension, Json, Router, extract::{Path, State}};
use uuid::Uuid;
use colored::Colorize;

use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyError, AccessPolicyPermissionLevel}, action::Action, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}};

#[axum::debug_handler]
async fn get_access_policy(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<AccessPolicy>, HTTPError> {

  // Make sure the access policy exists.
  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(|error| {
    
    let http_error = HTTPError::InternalServerError(Some(error.to_string()));
    eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
    return http_error;

  })?;
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
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;

      return Err(http_error);

    }

  };

  // Verify the principal has permission to get the access policy.
  let Some(user) = user else {

    let http_error = HTTPError::InternalServerError(Some(format!("Couldn't find a user for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.")));
    let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
    return Err(http_error);

  };

  let _ = ServerLogEntry::trace(&format!("Getting resource hierarchy for access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;
  let resource_hierarchy = match access_policy.get_hierarchy(&mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          let _ = ServerLogEntry::trace(&format!("Deleting orphaned access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;
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

  let _ = ServerLogEntry::trace(&format!("Getting action \"slashstep.accessPolicies.get\"..."), Some(&http_transaction.id), &mut postgres_client).await;
  let action = match Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"slashstep.accessPolicies.get\": {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Verifying principal's permissions to get access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;

  match PrincipalPermissionVerifier::verify_user_permissions(&user.id, &action.id, &resource_hierarchy, &AccessPolicyPermissionLevel::User, &mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = match error {
        PrincipalPermissionVerifierError::ForbiddenError { .. } => {
          
          if user.is_anonymous {

            HTTPError::UnauthorizedError(Some("You need at least user-level permission to the \"slashstep.accessPolicies.get\" action.".to_string()))

          } else {

            HTTPError::ForbiddenError(Some("You need at least user-level permission to the \"slashstep.accessPolicies.get\" action.".to_string()))
          
          }

        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  }

  let _ = ServerLogEntry::success(&format!("Successfully returned access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(access_policy));

}

async fn patch_access_policy() {


}

async fn delete_access_policy() {

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies/{access_policy_id}", axum::routing::get(get_access_policy))
    .route("/access-policies/{access_policy_id}", axum::routing::patch(patch_access_policy))
    .route("/access-policies/{access_policy_id}", axum::routing::delete(delete_access_policy))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;