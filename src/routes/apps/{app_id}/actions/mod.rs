/**
 * 
 * Any functionality for /apps/{app_id}/actions should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceType, ResourceError, access_policy::{ActionPermissionLevel}, action::{Action, ActionParentResourceType, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialActionProperties, InitialActionPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_app_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

#[axum::debug_handler]
async fn handle_list_actions_request(
  Path(app_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Action>>), HTTPError> {
  
  // Make sure the principal has access to list resources.
  let app_id = get_uuid_from_string(&app_id, "app", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("actions.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_app = get_app_by_id(&app_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::App, Some(&target_app.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_app_id = {}{}", 
    quote_literal(&app_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  let queried_resources = match Action::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

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
    target_resource_type: ResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "action" } else { "actions" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Action> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

#[axum::debug_handler]
async fn handle_create_action_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialActionPropertiesForPredefinedScope>, JsonRejection>
) -> Result<(StatusCode, Json<Action>), HTTPError> {

  let app_id = get_uuid_from_string(&app_id, "app", &http_transaction, &state.database_pool).await?;
  let action_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  // Make sure the user can create access policies for the target action.
  let target_app = get_app_by_id(&app_id, &http_transaction, &state.database_pool).await?;
  let create_actions_action = get_action_by_name("actions.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_actions_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::App, Some(&target_app.id), &create_actions_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the action.
  ServerLogEntry::trace(&format!("Creating action for authenticated_app {}...", target_app.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let created_action = match Action::create(&InitialActionProperties {
    name: action_properties_json.name.clone(),
    display_name: action_properties_json.display_name.clone(),
    description: action_properties_json.description.clone(),
    parent_app_id: Some(target_app.id),
    parent_resource_type: ActionParentResourceType::App
  }, &state.database_pool).await {

    Ok(created_action) => created_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create action: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let Some(_) = &authenticated_user { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Action,
    target_action_id: Some(created_action.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created action {}.", created_action.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(created_action)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps/{app_id}/actions", axum::routing::get(handle_list_actions_request))
    .route("/apps/{app_id}/actions", axum::routing::post(handle_create_action_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}

#[cfg(test)]
mod tests;