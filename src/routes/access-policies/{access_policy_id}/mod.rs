/**
 * 
 * Any functionality for /access-policies/{access_policy_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{DeletableResource, ResourceError, access_policy::{AccessPolicy, AccessPolicyPermissionLevel, EditableAccessPolicyProperties, ResourceHierarchy}, action::Action, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::{self, ResourceHierarchyError}, route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_authenticated_principal,verify_principal_permissions}}};

async fn get_resource_hierarchy(access_policy: &AccessPolicy, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<ResourceHierarchy, HTTPError> {

  ServerLogEntry::trace(&format!("Getting resource hierarchy for access policy {}...", access_policy.id), Some(&http_transaction.id), &database_pool).await.ok();
  let resource_hierarchy = match resource_hierarchy::get_hierarchy(&access_policy.scoped_resource_type, &access_policy.get_scoped_resource_id(), &database_pool).await {

    Ok(resource_hierarchy) => resource_hierarchy,

    Err(error) => {

      let http_error = match error {
        ResourceHierarchyError::ScopedResourceIDMissingError(scoped_resource_type) => {

          ServerLogEntry::trace(&format!("Deleting orphaned access policy {}...", access_policy.id), Some(&http_transaction.id), &database_pool).await.ok();
          let http_error = match access_policy.delete(&database_pool).await {

            Ok(_) => HTTPError::GoneError(Some(format!("The {} resource has been deleted because it was orphaned.", scoped_resource_type))),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to delete orphaned access policy: {:?}", error)))

          };
          
          http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
          return Err(http_error);

        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(resource_hierarchy);

}

async fn get_access_policy(access_policy_id: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AccessPolicy, HTTPError> {

  let access_policy_id = match Uuid::parse_str(&access_policy_id) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Getting access policy {}...", access_policy_id), Some(&http_transaction.id), &database_pool).await.ok();
  
  let access_policy = match AccessPolicy::get_by_id(&access_policy_id, &database_pool).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = match error {
        ResourceError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),
        ResourceError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        }
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();

      return Err(http_error);

    }

  };

  return Ok(access_policy);

}

async fn get_action_from_id(action_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Action, HTTPError> {

  ServerLogEntry::trace(&format!("Getting action {}", action_id), Some(&http_transaction.id), database_pool).await.ok();
  let action = match Action::get_by_id(action_id, database_pool).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action {}: {:?}", action_id, error)));
      http_error.print_and_save(Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(action);

}

/// GET /access-policies/{access_policy_id}
/// 
/// Gets a specific access policy by its ID.
#[axum::debug_handler]
async fn handle_get_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &state.database_pool).await?;
  let action = get_action_from_name("slashstep.accessPolicies.get", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  ServerLogEntry::success(&format!("Successfully returned access policy {}.", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  return Ok(Json(access_policy));

}

/// PATCH /access-policies/{access_policy_id}
/// 
/// Updates an access policy by its ID.
#[axum::debug_handler]
async fn handle_patch_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  body: Result<Json<EditableAccessPolicyProperties>, JsonRejection>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();

  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
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
      
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_from_name("slashstep.accessPolicies.update", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &state.database_pool).await?;
  let minimum_permission_level = match updated_access_policy_properties.permission_level {

    Some(permission_level) => if permission_level > AccessPolicyPermissionLevel::Editor { permission_level } else { AccessPolicyPermissionLevel::Editor },

    None => AccessPolicyPermissionLevel::Editor

  };
  verify_principal_permissions(&authenticated_principal, &access_policy_action, &resource_hierarchy, &http_transaction, &minimum_permission_level, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating access policy {}...", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let access_policy = match access_policy.update(&updated_access_policy_properties, &state.database_pool).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update access policy: {:?}", error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully updated access policy {}.", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(access_policy));

}

/// DELETE /access-policies/{access_policy_id}
/// 
/// Deletes an access policy by its ID.
#[axum::debug_handler]
async fn handle_delete_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<StatusCode, HTTPError> {

  let http_transaction = http_transaction.clone();
  let access_policy = get_access_policy(&access_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &http_transaction, &state.database_pool).await?;
  let delete_access_policy_action = get_action_from_name("slashstep.accessPolicies.delete", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &delete_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  let access_policy_action = get_action_from_id(&access_policy.action_id, &http_transaction, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::Editor, &state.database_pool).await?;

  match access_policy.delete(&state.database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete access policy: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  }

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted access policy {}.", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies/{access_policy_id}", axum::routing::get(handle_get_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::patch(handle_patch_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::delete(handle_delete_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}

#[cfg(test)]
mod tests;