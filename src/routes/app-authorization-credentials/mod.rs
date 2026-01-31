/**
 * 
 * Any functionality for /app-authorization-credentials should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./{app_authorization_credential_id}/mod.rs"]
mod app_authorization_credential_id;
// #[cfg(test)]
// mod tests;

use axum::Router;

use crate::{AppState, middleware::{authentication_middleware, http_request_middleware}};

// /// GET /app-authorizations
// /// 
// /// Lists app authorizations.
// #[axum::debug_handler]
// async fn handle_list_app_authorizations_request(
//   Query(query_parameters): Query<AppAuthorizationListQueryParameters>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>
// ) -> Result<ErasedJson, HTTPError> {

//   let resource_hierarchy = vec![(AccessPolicyResourceType::Instance, None)];
//   return list_app_authorizations(Query(query_parameters), State(state), Extension(http_transaction), Extension(authenticated_user), Extension(authenticated_app), resource_hierarchy, ActionLogEntryTargetResourceType::Instance, None).await;

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    // .route("/app-authorizations", axum::routing::get(handle_list_app_authorizations_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(app_authorization_credential_id::get_router(state.clone()));
  return router;

}