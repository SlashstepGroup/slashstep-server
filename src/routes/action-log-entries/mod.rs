use axum::Router;

use crate::{AppState, middleware::authentication_middleware};

#[path = "./{action_log_entry_id}/mod.rs"]
mod action_log_entry_id;

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(action_log_entry_id::get_router(state.clone()));
  return router;

}