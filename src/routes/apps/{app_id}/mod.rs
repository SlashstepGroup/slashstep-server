use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use crate::{
  AppState, 
  HTTPError, 
  middleware::authentication_middleware, 
  resources::{
    DeletableResource,
    access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, EditableAppProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_from_name, get_app_from_id, get_resource_hierarchy, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}
};

#[axum::debug_handler]
async fn handle_get_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<App>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_app = get_app_from_id(&app_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &mut postgres_client).await?;
  let get_apps_action = get_action_from_name("slashstep.apps.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &get_apps_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully returned app {}.", target_app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(target_app));

}

#[axum::debug_handler]
async fn handle_delete_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_app = get_app_from_id(&app_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &mut postgres_client).await?;
  let delete_actions_action = get_action_from_name("slashstep.apps.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  match target_app.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted app {}.", target_app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

#[axum::debug_handler]
async fn handle_patch_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<EditableAppProperties>, JsonRejection>
) -> Result<Json<App>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await.ok();
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
      
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  let original_target_app = get_app_from_id(&app_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_app, &AccessPolicyResourceType::App, &original_target_app.id, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.apps.update", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  ServerLogEntry::trace(&format!("Updating app {}...", original_target_app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let updated_target_action = match original_target_app.update(&updated_app_properties, &mut postgres_client).await {

    Ok(updated_target_action) => updated_target_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update app: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(updated_target_action.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully updated action {}.", updated_target_action.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(updated_target_action));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps/{action_id}", axum::routing::get(handle_get_app_request))
    .route("/apps/{action_id}", axum::routing::delete(handle_delete_app_request))
    .route("/apps/{action_id}", axum::routing::patch(handle_patch_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;