use axum::Router;
use crate::AppState;

#[path = "./oauth-authorizations/mod.rs"]
mod oauth_authorizations;

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .merge(oauth_authorizations::get_router(state.clone()));
  return router;

}