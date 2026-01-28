use std::sync::Arc;

use axum::{Extension, Router, extract::{Query, State}};
use axum_extra::response::ErasedJson;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType, IndividualPrincipal, ResourceHierarchy}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, AppError, DEFAULT_MAXIMUM_APP_LIST_LIMIT}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, match_db_error, match_slashstepql_error, verify_user_permissions}};

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

#[axum::debug_handler]
async fn handle_list_apps_request(
  Query(query_parameters): Query<AppListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<ErasedJson, HTTPError> {

  // Make sure the requestor has access to list apps.
  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let list_apps_action = get_action_from_name("slashstep.apps.list", &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Instance, None)];
  verify_user_permissions(&user, &list_apps_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  // Get the list of actions.
  let query = query_parameters.query.unwrap_or("".to_string());
  let apps = match App::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(apps) => apps,

    Err(error) => {

      let http_error = match error {

        AppError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_APP_LIST_LIMIT, "apps"),

        AppError::PostgresError(error) => match_db_error(&error, "apps"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list apps: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting apps..."), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let app_count = match App::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await {

    Ok(app_count) => app_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count apps: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await.ok();
  let app_list_length = apps.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", app_list_length, if app_list_length == 1 { "app" } else { "apps" }), Some(&http_transaction.id), &mut postgres_client).await.ok();
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
    .merge(app_id::get_router(state.clone()));
  return router;

}