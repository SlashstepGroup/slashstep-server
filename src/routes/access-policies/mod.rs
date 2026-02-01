/**
 * 
 * Any functionality for /access-policies should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::{AccessPolicy, AccessPolicyResourceType, DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT}, action_log_entry::ActionLogEntryTargetResourceType, app::App, http_transaction::HTTPTransaction, user::User}, utilities::{resource_hierarchy::ResourceHierarchy, reusable_route_handlers::{ResourceListQueryParameters, list_resources}}};

#[path = "./{access_policy_id}/mod.rs"]
mod access_policy_id;

/// GET /access-policies
/// 
/// Lists access policies.
#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<ErasedJson, HTTPError> {

  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  let response = list_resources(
    Query(query_parameters), 
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    resource_hierarchy, 
    ActionLogEntryTargetResourceType::Instance, 
    None, 
    |query, database_pool, individual_principal| Box::new(AccessPolicy::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(AccessPolicy::list(query, database_pool, individual_principal)),
    "slashstep.accessPolicies.list", 
    DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT,
    "access policies",
    "access policy"
  ).await;
  
  return response;

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies", axum::routing::get(handle_list_access_policies_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policy_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;