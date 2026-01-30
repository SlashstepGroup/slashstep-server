/**
 * 
 * Any functionality for /actions should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::AccessPolicyResourceType, action_log_entry::ActionLogEntryTargetResourceType, app::App, http_transaction::HTTPTransaction, user::User}, utilities::reusable_route_handlers::{ActionListQueryParameters, list_actions}};

#[path = "./{action_id}/mod.rs"]
pub mod action_id;

/// GET /actions
/// 
/// Lists actions.
#[axum::debug_handler]
async fn handle_list_actions_request(
  Query(query_parameters): Query<ActionListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<ErasedJson, HTTPError> {

  let resource_hierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  return list_actions(Query(query_parameters), State(state), Extension(http_transaction), Extension(authenticated_user), Extension(authenticated_app), resource_hierarchy, ActionLogEntryTargetResourceType::Instance, None).await;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions", axum::routing::get(handle_list_actions_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(action_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;