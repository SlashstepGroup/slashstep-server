use std::sync::Arc;

use axum::{Extension, Json, Router, extract::{Path, State}};

use crate::{AppState, HTTPError, resources::{access_policy::AccessPolicy, http_transaction::HTTPTransaction, user::User}};

#[path = "./{access_policy_id}/mod.rs"]
mod access_policy_id;

#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<Vec<AccessPolicy>>, HTTPError> {

  // let http_transaction = http_transaction.clone();
  // let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  // let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  // let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  // let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  // let action = get_action_from_name("slashstep.accessPolicies.get", &http_transaction, &mut postgres_client).await?;

  return Err(HTTPError::NotImplementedError(Some(format!("Not implemented."))));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies", axum::routing::get(handle_list_access_policies_request))
    .merge(access_policy_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;