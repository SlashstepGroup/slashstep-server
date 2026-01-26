use std::sync::Arc;
use axum::{Extension, Router, extract::{Path, Query, State}};
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{http_transaction::HTTPTransaction, user::User}, utilities::reusable_route_handlers::{AccessPolicyListQueryParameters, list_access_policies}};

#[cfg(test)]
mod tests;

#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Path(action_log_entry_id): Path<String>,
  Query(query_parameters): Query<AccessPolicyListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let query = format!(
    "scoped_resource_type = 'ActionLogEntry' AND scoped_action_log_entry_id = {}{}", 
    quote_literal(&action_log_entry_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  
  let query_parameters: AccessPolicyListQueryParameters = AccessPolicyListQueryParameters {
    query: Some(query)
  };

  return list_access_policies(Query(query_parameters), State(state), Extension(http_transaction), Extension(user)).await;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries/{action_log_entry_id}/access-policies", axum::routing::get(handle_list_access_policies_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user));
  return router;

}