/**
 * 
 * Any functionality for /apps should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{ResourceError, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, ResourceHierarchy}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, DEFAULT_MAXIMUM_APP_LIST_LIMIT}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_authenticated_principal, get_individual_principal_from_authenticated_principal, match_db_error, match_slashstepql_error, verify_principal_permissions}};

#[path = "./{app_id}/mod.rs"]
mod app_id;
#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
pub struct AppListQueryParameters {
  query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAppsResponseBody {
  apps: Vec<App>,
  total_count: i64
}

/// GET /apps
/// 
/// Lists apps.
#[axum::debug_handler]
async fn handle_list_apps_request(
  Query(query_parameters): Query<AppListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<ErasedJson, HTTPError> {

  // Make sure the requestor has access to list apps.
  let http_transaction = http_transaction.clone();
  let list_apps_action = get_action_from_name("slashstep.apps.list", &http_transaction, &state.database_pool).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &list_apps_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  // Get the list of actions.
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);
  let query = query_parameters.query.unwrap_or("".to_string());
  let apps = match App::list(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(apps) => apps,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_APP_LIST_LIMIT, "apps"),

        ResourceError::PostgresError(error) => match_db_error(&error, "apps"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list apps: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting apps..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let app_count = match App::count(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(app_count) => app_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count apps: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Instance,
    ..Default::default()
  }, &state.database_pool).await.ok();
  let app_list_length = apps.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", app_list_length, if app_list_length == 1 { "authenticated_app" } else { "apps" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListAppsResponseBody {
    apps,
    total_count: app_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps", axum::routing::get(handle_list_apps_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(app_id::get_router(state.clone()));
  return router;

}