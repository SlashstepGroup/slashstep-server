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
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action::{Action, ActionParentResourceType, DEFAULT_MAXIMUM_ACTION_LIST_LIMIT, InitialActionProperties, InitialActionPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_app_from_id, get_authenticated_principal, get_resource_hierarchy, verify_principal_permissions}}};

#[axum::debug_handler]
async fn handle_list_actions_request(
  Path(app_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&app, &AccessPolicyResourceType::App, &app.id, &http_transaction, &state.database_pool).await?;

  let query = format!(
    "parent_app_id = {}{}", 
    quote_literal(&app_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  
  let query_parameters = ResourceListQueryParameters {
    query: Some(query)
  };

  let response = list_resources(
    Query(query_parameters), 
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    resource_hierarchy, 
    ActionLogEntryTargetResourceType::Action, 
    Some(app.id), 
    |query, database_pool, individual_principal| Box::new(Action::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(Action::list(query, database_pool, individual_principal)),
    "slashstep.actions.list", 
    DEFAULT_MAXIMUM_ACTION_LIST_LIMIT,
    "apps",
    "app"
  ).await;
  
  return response;

}

#[axum::debug_handler]
async fn handle_create_action_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  body: Result<Json<InitialActionPropertiesForPredefinedScope>, JsonRejection>
) -> Result<(StatusCode, Json<Action>), HTTPError> {

  let http_transaction = http_transaction.clone();

  // Verify the request body.
  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let action_properties_json = match body {

    Ok(action_properties_json) => action_properties_json,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  // Make sure the user can create access policies for the target action.
  let target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &state.database_pool).await?;
  let create_actions_action = get_action_from_name("slashstep.actions.create", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &create_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

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
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
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
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}

#[cfg(test)]
mod tests;