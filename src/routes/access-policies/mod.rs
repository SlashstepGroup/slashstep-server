use axum::Router;

use crate::AppState;

#[path = "./{access_policy_id}/mod.rs"]
mod access_policy_id;

async fn list_access_policies() {

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let mut router = Router::<AppState>::new();
  router = router.route("/access-policies", axum::routing::get(list_access_policies));
  router = router.merge(access_policy_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;