#[path = "./access-policies/mod.rs"]
mod access_policies;
mod actions;
#[path = "./action-log-entries/mod.rs"]
mod action_log_entries;
mod apps;
#[path = "./app-authorizations/mod.rs"]
mod app_authorizations;
#[path = "./app-authorization-credentials/mod.rs"]
mod app_authorization_credentials;
#[path = "./app-credentials/mod.rs"]
mod app_credentials;
mod fields;
#[path = "./field-choices/mod.rs"]
mod field_choices;
#[path = "./field-values/mod.rs"]
mod field_values;
mod groups;
#[path = "./http-transactions/mod.rs"]
mod http_transactions;
mod items;
#[path = "./item-connections/mod.rs"]
mod item_connections;
#[path = "./item-connection-types/mod.rs"]
mod item_connection_types;
#[path = "./memberships/mod.rs"]
mod memberships;
mod milestones;
#[path = "./oauth-access-tokens/mod.rs"]
mod oauth_access_tokens;
mod projects;
mod roles;
#[path = "./server-log-entries/mod.rs"]
mod server_log_entries;
mod sessions;
mod users;
mod workspaces;

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
    .merge(app_authorizations::get_router(state.clone()))
    .merge(app_authorization_credentials::get_router(state.clone()))
    .merge(app_credentials::get_router(state.clone()))
    .merge(fields::get_router(state.clone()))
    .merge(field_choices::get_router(state.clone()))
    .merge(field_values::get_router(state.clone()))
    .merge(groups::get_router(state.clone()))
    .merge(http_transactions::get_router(state.clone()))
    .merge(items::get_router(state.clone()))
    .merge(item_connections::get_router(state.clone()))
    .merge(item_connection_types::get_router(state.clone()))
    .merge(memberships::get_router(state.clone()))
    .merge(milestones::get_router(state.clone()))
    .merge(oauth_access_tokens::get_router(state.clone()))
    .merge(projects::get_router(state.clone()))
    .merge(roles::get_router(state.clone()))
    .merge(server_log_entries::get_router(state.clone()))
    .merge(sessions::get_router(state.clone()))
    .merge(users::get_router(state.clone()))
    .fallback(fallback);
  return router;

}
