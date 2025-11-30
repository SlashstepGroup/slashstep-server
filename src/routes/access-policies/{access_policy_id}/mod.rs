use axum::{Extension, Json, Router, extract::{Path, State}};
use uuid::Uuid;
use colored::Colorize;

use crate::{AppState, HTTPError, RequestData, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyError}, server_log_entry::ServerLogEntry}};

#[axum::debug_handler]
async fn get_access_policy(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(request_data): Extension<RequestData>
) -> Result<Json<AccessPolicy>, HTTPError> {

  // Make sure the access policy exists.
  let http_request = request_data.http_request.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(|error| {
    
    let http_error = HTTPError::InternalServerError(Some(error.to_string()));
    eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
    return http_error;

  })?;
  let access_policy_id = match Uuid::parse_str(&access_policy_id) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_request.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Getting access policy {}...", access_policy_id), Some(&http_request.id), &mut postgres_client).await;
  
  let access_policy = match AccessPolicy::get_by_id(&access_policy_id, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_request.id), &mut postgres_client).await;

      return Err(http_error);

    }

  };

  // Verify the principal has permission to get the access policy.
  let _ = ServerLogEntry::trace(&format!("Verifying principal's permissions to get access policy {}...", access_policy_id), Some(&http_request.id), &mut postgres_client).await;

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