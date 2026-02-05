use axum::Router;
use crate::AppState;

#[path = "./{user_id}/mod.rs"]
mod user_id;

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .merge(user_id::get_router(state.clone()));
  return router;

}