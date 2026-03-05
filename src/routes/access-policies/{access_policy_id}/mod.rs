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
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{DeletableResource, access_policy::{AccessPolicy, ResourceType, ActionPermissionLevel, EditableAccessPolicyProperties}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{route_handler_utilities::{AuthenticatedPrincipal, get_access_policy_by_id, get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /access-policies/{access_policy_id}
/// 
/// Gets a specific access policy by its ID.
#[axum::debug_handler]
async fn handle_get_access_policy_request(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<AccessPolicy>, HTTPError> {

  // Make sure the access policy exists.
  let access_policy_id = get_uuid_from_string(&access_policy_id, "access policy", &http_transaction, &state.database_pool).await?;
  let access_policy = get_access_policy_by_id(&access_policy_id, &http_transaction, &state.database_pool).await?;

  // Make sure the delegate and principal have access to the resource.
  let action = get_action_by_name("accessPolicies.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &ResourceType::AccessPolicy, &access_policy.id, &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  // Return the access policy.
  ServerLogEntry::success(&format!("Successfully returned access policy {}.", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();

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
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableAccessPolicyProperties>, JsonRejection>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let access_policy_id = get_uuid_from_string(&access_policy_id, "access policy", &http_transaction, &state.database_pool).await?;
  let updated_access_policy_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  // Make sure the delegate and principal have access to the resource.
  let access_policy = get_access_policy_by_id(&access_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&access_policy, &ResourceType::AccessPolicy, &access_policy.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("accessPolicies.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  let access_policy_action = get_action_by_id(&access_policy.action_id, &http_transaction, &state.database_pool).await?;
  let minimum_permission_level = match updated_access_policy_properties.permission_level {

    Some(permission_level) => if permission_level > ActionPermissionLevel::Editor { permission_level } else { ActionPermissionLevel::Editor },

    None => ActionPermissionLevel::Editor

  };
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &access_policy_action.id, &http_transaction.id, &minimum_permission_level, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &access_policy_action, &resource_hierarchy, &http_transaction, &minimum_permission_level, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating access policy {}...", access_policy_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let access_policy = match access_policy.update(&updated_access_policy_properties, &state.database_pool).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update access policy: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
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
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let access_policy_id = get_uuid_from_string(&access_policy_id, "access policy", &http_transaction, &state.database_pool).await?;
  let target_access_policy = get_access_policy_by_id(&access_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_access_policy, &ResourceType::AccessPolicy, &target_access_policy.id, &http_transaction, &state.database_pool).await?;
  let delete_resources_action = get_action_by_name("accessPolicies.delete", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &delete_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &delete_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  if let Err(error) = target_access_policy.delete(&state.database_pool).await {

    let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete access policy {}: {:?}", target_access_policy.id, error)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(target_access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully deleted access policy {}.", target_access_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(StatusCode::NO_CONTENT);

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/access-policies/{access_policy_id}", axum::routing::get(handle_get_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::patch(handle_patch_access_policy_request))
    .route("/access-policies/{access_policy_id}", axum::routing::delete(handle_delete_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}

#[cfg(test)]
mod tests;