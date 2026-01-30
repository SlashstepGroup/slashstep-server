#[path = "./access-policies/mod.rs"]
mod access_policies;
mod actions;
#[path = "./action-log-entries/mod.rs"]
mod action_log_entries;
mod apps;

use axum::{Router, response::IntoResponse};
use crate::{AppState, HTTPError, middleware::http_request_middleware};

async fn fallback() -> impl IntoResponse {

  return HTTPError::NotFoundError(None);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()))
    .merge(actions::get_router(state.clone()))
    .merge(action_log_entries::get_router(state.clone()))
    .merge(apps::get_router(state.clone()))
    .fallback(fallback);
  return router;

}