use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::AccessPolicyResourceType, action_log_entry::ActionLogEntryTargetResourceType, http_transaction::HTTPTransaction, user::User}, utilities::reusable_route_handlers::{ActionListQueryParameters, list_actions}};

#[path = "./{action_id}/mod.rs"]
pub mod action_id;

#[axum::debug_handler]
async fn handle_list_actions_request(
  Query(query_parameters): Query<ActionListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  let resource_hierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  return list_actions(Query(query_parameters), State(state), Extension(http_transaction), Extension(user), resource_hierarchy, ActionLogEntryTargetResourceType::Instance, None).await;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions", axum::routing::get(handle_list_actions_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(action_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;