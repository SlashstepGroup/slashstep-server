use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{
  AppState, 
  HTTPError, 
  middleware::authentication_middleware, 
  resources::{
    access_policy::{
      AccessPolicyPermissionLevel, 
      AccessPolicyResourceType, 
      ResourceHierarchy
    }, 
    action::{
      Action, 
      ActionError, EditableActionProperties
    }, 
    http_transaction::HTTPTransaction, 
    server_log_entry::ServerLogEntry, 
    user::User
  }, 
  utilities::{
    resource_hierarchy::{
      self, 
      ResourceHierarchyError
    }, 
    route_handler_utilities::{
      get_action_from_name, 
      get_user_from_option_user, 
      map_postgres_error_to_http_error, 
      verify_user_permissions
    }
  }
};

async fn get_resource_hierarchy(action: &Action, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting resource hierarchy for action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await;
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&AccessPolicyResourceType::Action, &Some(action.id), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          let _ = ServerLogEntry::trace(&format!("Deleting orphaned action {}...", action.id), Some(&http_transaction.id), &mut postgres_client).await;
          let http_error = match action.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned action: {:?}", error)))

          };
          
          let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
          return Err(http_error);

        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

async fn get_action_from_id(action_id_string: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  let action_id = match Uuid::parse_str(&action_id_string) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the action ID.".to_string()));
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Getting action {}...", action_id), Some(&http_transaction.id), postgres_client).await;
  let action = match Action::get_by_id(&action_id, postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = match error {
        
        ActionError::NotFoundError(message) => HTTPError::NotFoundError(Some(message)),

        error => HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)))

      };
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(action);

}

#[axum::debug_handler]
async fn handle_get_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&action, &http_transaction, &mut postgres_client).await?;
  let get_actions_action = get_action_from_name("slashstep.actions.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &get_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  let _ = ServerLogEntry::success(&format!("Successfully returned action {}.", action_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(action));

}

#[axum::debug_handler]
async fn handle_patch_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<EditableActionProperties>, JsonRejection>
) -> Result<Json<Action>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  let _ = ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await;
  let updated_action_properties = match body {

    Ok(updated_action_properties) => updated_action_properties,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let original_action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_action, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.actions.update", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  let _ = ServerLogEntry::trace(&format!("Updating action {}...", action_id), Some(&http_transaction.id), &mut postgres_client).await;
  let updated_action = match original_action.update(&updated_action_properties, &mut postgres_client).await {

    Ok(updated_action) => updated_action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update action: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::success(&format!("Successfully updated action {}.", action_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(updated_action));

}

#[axum::debug_handler]
async fn handle_delete_action_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&action, &http_transaction, &mut postgres_client).await?;
  let delete_actions_action = get_action_from_name("slashstep.actions.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_actions_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  match action.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete action: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  }

  let _ = ServerLogEntry::success(&format!("Successfully deleted action {}.", action_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions/{action_id}", axum::routing::get(handle_get_action_request))
    .route("/actions/{action_id}", axum::routing::patch(handle_patch_action_request))
    .route("/actions/{action_id}", axum::routing::delete(handle_delete_action_request))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;