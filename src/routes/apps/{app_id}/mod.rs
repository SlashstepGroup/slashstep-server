/**
 * 
 * Any functionality for /apps/{app_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    DeletableResource, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, EditableAppProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_app_from_id, get_authenticated_principal, get_resource_hierarchy, verify_principal_permissions}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
mod actions;
#[path = "./app-credentials/mod.rs"]
mod app_credentials;
#[cfg(test)]
mod tests;

/// GET /apps/{app_id}
/// 
/// Gets an app by its ID.
#[axum::debug_handler]
async fn handle_get_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<Json<App>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &state.database_pool).await?;
  let get_apps_action = get_action_from_name("slashstep.apps.get", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &get_apps_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned authenticated_app {}.", target_app.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_app));

}

/// DELETE /apps/{app_id}
/// 
/// Deletes an app by its ID.
#[axum::debug_handler]
async fn handle_delete_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &state.database_pool).await?;
  let delete_actions_action = get_action_from_name("slashstep.apps.delete", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &delete_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  match target_app.delete(&state.database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete authenticated_app: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted authenticated_app {}.", target_app.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

/// PATCH /apps/{app_id}
/// 
/// Updates an app by its ID.
#[axum::debug_handler]
async fn handle_patch_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  body: Result<Json<EditableAppProperties>, JsonRejection>
) -> Result<Json<App>, HTTPError> {

  let http_transaction = http_transaction.clone();

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_app_properties = match body {

    Ok(updated_app_properties) => updated_app_properties,

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

  let original_target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_app, &AccessPolicyResourceType::App, &original_target_app.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_from_name("slashstep.apps.update", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating authenticated_app {}...", original_target_app.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_action = match original_target_app.update(&updated_app_properties, &state.database_pool).await {

    Ok(updated_target_action) => updated_target_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update authenticated_app: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(updated_target_action.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated action {}.", updated_target_action.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_action));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps/{action_id}", axum::routing::get(handle_get_app_request))
    .route("/apps/{action_id}", axum::routing::delete(handle_delete_app_request))
    .route("/apps/{action_id}", axum::routing::patch(handle_patch_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(actions::get_router(state.clone()))
    .merge(access_policies::get_router(state.clone()))
    .merge(app_credentials::get_router(state.clone()));
  return router;

}
