/**
 * 
 * Any functionality for /workspaces should be handled here.
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
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::AccessPolicyResourceType, action_log_entry::ActionLogEntryTargetResourceType, app::{App, DEFAULT_MAXIMUM_APP_LIST_LIMIT}, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, user::User}, utilities::reusable_route_handlers::{ResourceListQueryParameters, list_resources}};

#[path = "./{workspace_id}/mod.rs"]
mod workspace_id;
#[cfg(test)]
mod tests;

// /// GET /workspaces
// /// 
// /// Lists apps.
// #[axum::debug_handler]
// async fn handle_list_apps_request(
//   Query(query_parameters): Query<ResourceListQueryParameters>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>,
//   Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
// ) -> Result<ErasedJson, HTTPError> {

//   let resource_hierarchy = vec![(AccessPolicyResourceType::Server, None)];
//   let response = list_resources(
//     Query(query_parameters), 
//     State(state), 
//     Extension(http_transaction), 
//     Extension(authenticated_user), 
//     Extension(authenticated_app), 
//     Extension(authenticated_app_authorization),
//     resource_hierarchy, 
//     ActionLogEntryTargetResourceType::Server, 
//     None, 
//     |query, database_pool, individual_principal| Box::new(App::count(query, database_pool, individual_principal)),
//     |query, database_pool, individual_principal| Box::new(App::list(query, database_pool, individual_principal)),
//     "slashstep.apps.list", 
//     DEFAULT_MAXIMUM_APP_LIST_LIMIT,
//     "apps",
//     "app"
//   ).await;

//   return response;

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    // .route("/workspaces", axum::routing::get(handle_list_apps_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(workspace_id::get_router(state.clone()));
  return router;

}