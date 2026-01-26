use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyError, AccessPolicyPermissionLevel, EditableAccessPolicyProperties, ResourceHierarchy}, action::Action, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, http_transaction::{HTTPTransaction}, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::{self, ResourceHierarchyError}, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}}};

async fn get_resource_hierarchy(access_policy: &AccessPolicy, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, HTTPError> {

  ServerLogEntry::trace(&format!("Getting resource hierarchy for access policy {}...", access_policy.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&access_policy.scoped_resource_type, &access_policy.get_scoped_resource_id(), &mut postgres_client).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned access policy {}...", access_policy.id), Some(&http_transaction.id), &mut postgres_client).await.ok();
          let http_error = match access_policy.delete(&mut postgres_client).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned access policy: {:?}", error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
          return Err(http_error);

        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

async fn get_access_policy(access_policy_id: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<AccessPolicy, HTTPError> {

  let access_policy_id = match Uuid::parse_str(&access_policy_id) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  
  let access_policy = match AccessPolicy::get_by_id(&access_policy_id, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),
        AccessPolicyError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        }
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await.ok();

      return Err(http_error);

    }

  };

  return Ok(access_policy);

}

async fn get_action_from_id(action_id: &Uuid, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  ServerLogEntry::trace(&format!("Getting action {}", action_id), Some(&http_transaction.id), postgres_client).await.ok();
  let action = match Action::get_by_id(action_id, postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

#[axum::debug_handler]
async fn handle_get_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let action = get_action_from_name("slashstep.accessPolicies.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ServerLogEntry::success(&format!("Successfully returned access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();

  return Ok(Json(access_policy));

}


#[axum::debug_handler]
async fn handle_patch_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<EditableAccessPolicyProperties>, JsonRejection>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await.ok();
  let updated_access_policy_properties = match body {

    Ok(updated_access_policy_properties) => updated_access_policy_properties,

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

  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.accessPolicies.update", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &mut postgres_client).await?;
  let minimum_permission_level = match updated_access_policy_properties.permission_level {

    Some(permission_level) => if permission_level > AccessPolicyPermissionLevel::Editor { permission_level } else { AccessPolicyPermissionLevel::Editor },

    None => AccessPolicyPermissionLevel::Editor

  };
  verify_user_permissions(&user, &access_policy_action, &resource_hierarchy, &http_transaction, &minimum_permission_level, &mut postgres_client).await?;

  ServerLogEntry::trace(&format!("Updating access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await.ok();
  let access_policy = match access_policy.update(&updated_access_policy_properties, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update access policy: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();

  ServerLogEntry::success(&format!("Successfully updated access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(access_policy));

}

#[axum::debug_handler]
async fn handle_delete_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &mut postgres_client).await?;
  let delete_access_policy_action = get_action_from_name("slashstep.accessPolicies.delete", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &delete_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::Editor, &mut postgres_client).await?;

  match access_policy.delete(&mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete access policy: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted access policy {}.", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies/{access_policy_id}", axum::routing::get(handle_get_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::patch(handle_patch_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::delete(handle_delete_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;