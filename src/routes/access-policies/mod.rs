use std::sync::Arc;

use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{http_transaction::HTTPTransaction, user::User}, utilities::reusable_route_handlers::{AccessPolicyListQueryParameters, list_access_policies}};

#[path = "./{access_policy_id}/mod.rs"]
mod access_policy_id;

#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Query(query_parameters): Query<AccessPolicyListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  return list_access_policies(Query(query_parameters), State(state), Extension(http_transaction), Extension(user)).await;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies", axum::routing::get(handle_list_access_policies_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(access_policy_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;