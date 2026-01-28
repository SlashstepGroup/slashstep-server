use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyResourceType, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action::{Action, ActionParentResourceType, InitialActionProperties, InitialActionPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{AccessPolicyListQueryParameters, list_access_policies}, route_handler_utilities::{get_action_from_id, get_action_from_name, get_app_from_id, get_resource_hierarchy, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}}};

// #[axum::debug_handler]
// async fn handle_list_access_policies_request(
//   Path(action_id): Path<String>,
//   Query(query_parameters): Query<AccessPolicyListQueryParameters>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(user): Extension<Option<Arc<User>>>
// ) -> Result<ErasedJson, HTTPError> {

//   let query = format!(
//     "scoped_resource_type = 'Action' AND scoped_action_id = {}{}", 
//     quote_literal(&action_id.to_string()), 
//     query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
//   );
  
//   let query_parameters = AccessPolicyListQueryParameters {
//     query: Some(query)
//   };

//   return list_access_policies(Query(query_parameters), State(state), Extension(http_transaction), Extension(user)).await;

// }

#[axum::debug_handler]
async fn handle_create_action_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<InitialActionPropertiesForPredefinedScope>, JsonRejection>
) -> Result<(StatusCode, Json<Action>), HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  // Verify the request body.
  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await.ok();
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
      
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  // Make sure the user can create access policies for the target action.
  let target_app = get_app_from_id(&app_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &mut postgres_client).await?;
  let create_actions_action = get_action_from_name("slashstep.actions.create", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &create_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  // Create the action.
  ServerLogEntry::trace(&format!("Creating action for app {}...", target_app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let created_action = match Action::create(&InitialActionProperties {
    name: action_properties_json.name.clone(),
    display_name: action_properties_json.display_name.clone(),
    description: action_properties_json.description.clone(),
    app_id: Some(target_app.id),
    parent_resource_type: ActionParentResourceType::App
  }, &mut postgres_client).await {

    Ok(created_action) => created_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create action: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error)

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_actions_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::Action,
    target_action_id: Some(created_action.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully created action {}.", created_action.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok((StatusCode::CREATED, Json(created_action)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    // .route("/actions/{action_id}/access-policies", axum::routing::get(handle_list_access_policies_request))
    .route("/apps/{app_id}/actions", axum::routing::post(handle_create_action_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;