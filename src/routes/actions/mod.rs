/**
 * 
 * Any functionality for /actions should be handled here.
 * 
 * Creating server level actions through the REST API is unsupported because server level actions are intended to be created by Slashstep Server.
 * All other actions should be app level.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Query, State}};
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, access_policy::{ActionPermissionLevel, ResourceType}, action::{Action, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

#[path = "./{action_id}/mod.rs"]
pub mod action_id;

/// GET /actions
/// 
/// Lists actions.
#[axum::debug_handler]
async fn handle_list_actions_request(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Action>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let list_resources_action = get_action_by_name("actions.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Server, None, &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace("Listing actions...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let query = query_parameters.query.unwrap_or("".to_string());
  let queried_resources = match Action::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_actions) => queried_actions,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "actions"),

        ResourceError::PostgresError(error) => match_db_error(&error, "actions"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list actions: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting actions..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Action::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count actions: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Server,
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_action_log_entry_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_action_log_entry_list_length, if queried_action_log_entry_list_length == 1 { "action log entry" } else { "action log entries" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Action> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions", axum::routing::get(handle_list_actions_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(action_id::get_router(state.clone()));
  return router;

}

#[cfg(test)]
mod tests;