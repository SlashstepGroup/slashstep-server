use axum::Router;
use crate::{AppState, middleware::http_request_middleware};

#[path = "./{app_authorization_id}/mod.rs"]
mod app_authorization_id;

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(app_authorization_id::get_router(state.clone()));
  return router;

}