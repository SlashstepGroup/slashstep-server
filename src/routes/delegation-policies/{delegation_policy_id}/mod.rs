/**
 * 
 * Any functionality for /delegation-policies/{delegation_policy_id} should be handled here.
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
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App}, app_authorization::AppAuthorization, delegation_policy::{DelegationPolicy, EditableDelegationPolicyProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::{reusable_route_handlers::delete_resource, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_delegation_policy_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}
};

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[cfg(test)]
mod tests;

/// GET /delegation-policies/{delegation_policy_id}
/// 
/// Gets an delegation_policy by its ID.
#[axum::debug_handler]
async fn handle_get_delegation_policy_request(
  Path(delegation_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<DelegationPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let delegation_policy_id = get_uuid_from_string(&delegation_policy_id, "delegation policy", &http_transaction, &state.database_pool).await?;
  let target_delegation_policy = get_delegation_policy_by_id(&delegation_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_delegation_policy, &AccessPolicyResourceType::DelegationPolicy, &target_delegation_policy.id, &http_transaction, &state.database_pool).await?;
  let get_delegation_policies_action = get_action_by_name("slashstep.delegationPolicies.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_delegation_policies_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &get_delegation_policies_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_delegation_policies_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::DelegationPolicy,
    target_delegation_policy_id: Some(target_delegation_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned delegation policy {}.", target_delegation_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_delegation_policy));

}

/// DELETE /delegation_policies/{delegation_policy_id}
/// 
/// Deletes a delegation policy by its ID.
#[axum::debug_handler]
async fn handle_delete_delegation_policy_request(
  Path(delegation_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<StatusCode, HTTPError> {

  let delegation_policy_id = get_uuid_from_string(&delegation_policy_id, "delegation policy", &http_transaction, &state.database_pool).await?;
  let response = delete_resource(
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    Some(&AccessPolicyResourceType::DelegationPolicy),
    &delegation_policy_id, 
    "slashstep.delegationPolicies.delete",
    "delegation policy",
    &ActionLogEntryTargetResourceType::DelegationPolicy,
    |delegation_policy_id, database_pool| Box::new(DelegationPolicy::get_by_id(delegation_policy_id, database_pool))
  ).await;

  return response;

}

/// PATCH /delegation_policies/{delegation_policy_id}
/// 
/// Updates a delegation policy by its ID.
#[axum::debug_handler]
async fn handle_patch_delegation_policy_request(
  Path(delegation_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<EditableDelegationPolicyProperties>, JsonRejection>
) -> Result<Json<DelegationPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let updated_delegation_policy_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let delegation_policy_id = get_uuid_from_string(&delegation_policy_id, "delegation policy", &http_transaction, &state.database_pool).await?;
  let original_target_delegation_policy = get_delegation_policy_by_id(&delegation_policy_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&original_target_delegation_policy, &AccessPolicyResourceType::DelegationPolicy, &original_target_delegation_policy.id, &http_transaction, &state.database_pool).await?;
  let update_access_policy_action = get_action_by_name("slashstep.delegationPolicies.update", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace(&format!("Updating delegation policy {}...", original_target_delegation_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let updated_target_delegation_policy = match original_target_delegation_policy.update(&updated_delegation_policy_properties, &state.database_pool).await {

    Ok(updated_target_delegation_policy) => updated_target_delegation_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update delegation policy {}: {:?}", original_target_delegation_policy.id, error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_access_policy_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::DelegationPolicy,
    target_delegation_policy_id: Some(updated_target_delegation_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully updated delegation policy {}.", updated_target_delegation_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(updated_target_delegation_policy));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/delegation-policies/{delegation_policy_id}", axum::routing::get(handle_get_delegation_policy_request))
    .route("/delegation-policies/{delegation_policy_id}", axum::routing::delete(handle_delete_delegation_policy_request))
    .route("/delegation-policies/{delegation_policy_id}", axum::routing::patch(handle_patch_delegation_policy_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(access_policies::get_router(state.clone()));
  return router;

}
