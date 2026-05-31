#[path = "./access-policies/mod.rs"]
pub mod access_policies;
#[path = "./action-log-entries/mod.rs"]
pub mod action_log_entries;
pub mod actions;
#[path = "./app-authorization-credentials/mod.rs"]
pub mod app_authorization_credentials;
#[path = "./app-authorizations/mod.rs"]
pub mod app_authorizations;
#[path = "./app-credentials/mod.rs"]
pub mod app_credentials;
pub mod apps;
pub mod configurations;
#[path = "./delegation-policies/mod.rs"]
pub mod delegation_policies;
#[path = "./field-choices/mod.rs"]
pub mod field_choices;
#[path = "./field-values/mod.rs"]
pub mod field_values;
pub mod fields;
pub mod groups;
#[path = "./http-transactions/mod.rs"]
pub mod http_transactions;
#[path = "./item-connection-types/mod.rs"]
pub mod item_connection_types;
#[path = "./item-connections/mod.rs"]
pub mod item_connections;
#[path = "./item-type-icons/mod.rs"]
pub mod item_type_icons;
#[path = "./item-types/mod.rs"]
pub mod item_types;
pub mod items;
pub mod iterations;
#[path = "./membership-invitations/mod.rs"]
pub mod membership_invitations;
pub mod memberships;
pub mod milestones;
#[path = "./oauth-access-tokens/mod.rs"]
pub mod oauth_access_tokens;
pub mod projects;
pub mod roles;
// #[path = "./server-log-entries/mod.rs"]
// pub mod server_log_entries;
#[path = "./session-credentials/mod.rs"]
pub mod session_credentials;
pub mod sessions;
pub mod statuses;
pub mod users;
#[path = "./view-fields/mod.rs"]
pub mod view_fields;
pub mod views;
pub mod workspaces;

use crate::{
    AppState, HTTPError,
    middleware::http_transaction_middleware,
    resources::app::{AppClientType, AppParentResourceType},
};
use axum::{Router, response::IntoResponse};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ResourceListQueryParameters {
    pub query: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetResourceResponseBody<ResourceStruct> {
    pub data: ResourceStruct,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PatchResourceResponseBody<ResourceStruct> {
    pub data: ResourceStruct,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateResourceResponseBody<ResourceStruct> {
    pub data: ResourceStruct,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResourcesResponseBody<ResourceStruct> {
    pub data: Vec<ResourceStruct>,
    pub total_count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateAppRequestBody {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub client_type: AppClientType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppWithClientSecret {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub client_type: AppClientType,
    pub client_secret: Option<String>,
    pub parent_resource_type: AppParentResourceType,
    pub parent_workspace_id: Option<Uuid>,
    pub parent_user_id: Option<Uuid>,
}

async fn fallback() -> impl IntoResponse {
    HTTPError::NotFoundError(None)
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http_transaction_middleware::create_http_transaction,
        ))
        .merge(access_policies::get_router(state.clone()))
        .merge(actions::get_router(state.clone()))
        .merge(action_log_entries::get_router(state.clone()))
        .merge(apps::get_router(state.clone()))
        .merge(app_authorizations::get_router(state.clone()))
        .merge(app_authorization_credentials::get_router(state.clone()))
        .merge(app_credentials::get_router(state.clone()))
        .merge(configurations::get_router(state.clone()))
        .merge(delegation_policies::get_router(state.clone()))
        .merge(fields::get_router(state.clone()))
        .merge(field_choices::get_router(state.clone()))
        .merge(field_values::get_router(state.clone()))
        .merge(groups::get_router(state.clone()))
        .merge(http_transactions::get_router(state.clone()))
        .merge(items::get_router(state.clone()))
        .merge(item_connections::get_router(state.clone()))
        .merge(item_connection_types::get_router(state.clone()))
        .merge(item_types::get_router(state.clone()))
        .merge(item_type_icons::get_router(state.clone()))
        .merge(iterations::get_router(state.clone()))
        .merge(memberships::get_router(state.clone()))
        .merge(membership_invitations::get_router(state.clone()))
        .merge(milestones::get_router(state.clone()))
        .merge(oauth_access_tokens::get_router(state.clone()))
        .merge(projects::get_router(state.clone()))
        .merge(roles::get_router(state.clone()))
        // .merge(server_log_entries::get_router(state.clone()))
        .merge(sessions::get_router(state.clone()))
        .merge(session_credentials::get_router(state.clone()))
        .merge(statuses::get_router(state.clone()))
        .merge(users::get_router(state.clone()))
        .merge(views::get_router(state.clone()))
        .merge(view_fields::get_router(state.clone()))
        .merge(workspaces::get_router(state.clone()))
        .fallback(fallback)
        .layer(TraceLayer::new_for_http())
}
