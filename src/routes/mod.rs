#[path = "./access-policies/mod.rs"]
mod access_policies;

use axum::{Router, response::IntoResponse};
use crate::{AppState, HTTPError};

async fn fallback() -> impl IntoResponse {

  return HTTPError::NotFoundError(None);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .merge(access_policies::get_router(state.clone()))
    .fallback(fallback);
  return router;

}