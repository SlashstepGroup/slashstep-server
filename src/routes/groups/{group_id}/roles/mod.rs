/**
 * 
 * Any functionality for /groups/{group_id}/roles should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::{sync::Arc};
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, role::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialRoleProperties, InitialRolePropertiesWithPredefinedParent, Role, RoleParentResourceType}, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_group_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /groups/{group_id}/roles
/// 
/// Lists roles for an app.
#[axum::debug_handler]
pub async fn handle_list_roles_request(
  Path(group_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&group, &AccessPolicyResourceType::Group, &group.id, &http_transaction, &state.database_pool).await?;

  let query = format!(
    "parent_group_id = {}{}", 
    quote_literal(&group_id.to_string()), 
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
    Extension(authenticated_app_authorization),
    resource_hierarchy, 
    ActionLogEntryTargetResourceType::Group, 
    Some(group.id), 
    |query, database_pool, individual_principal| Box::new(Role::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(Role::list(query, database_pool, individual_principal)),
    "roles.list", 
    DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
    "roles",
    "role"
  ).await;
  
  return response;

}

/// POST /groups/{group_id}/roles
/// 
/// Creates an role for an app.
#[axum::debug_handler]
async fn handle_create_role_request(
  Path(group_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialRolePropertiesWithPredefinedParent>, JsonRejection>
) -> Result<(StatusCode, Json<Role>), HTTPError> {

  let partial_role_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_group, &AccessPolicyResourceType::Group, &target_group.id, &http_transaction, &state.database_pool).await?;
  let create_roles_action = get_action_by_name("roles.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_roles_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_roles_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the role.
  ServerLogEntry::trace(&format!("Creating role on group {}...", target_group.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let created_role = match Role::create(&InitialRoleProperties {
    name: partial_role_properties.name.clone(),
    display_name: partial_role_properties.display_name.clone(),
    description: partial_role_properties.description.clone(),
    parent_resource_type: RoleParentResourceType::Group,
    parent_group_id: Some(target_group.id),
    parent_project_id: None,
    parent_workspace_id: None,
    protected_role_type: None
  }, &state.database_pool).await {

    Ok(created_role) => created_role,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create role: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_roles_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Role,
    target_role_id: Some(created_role.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created role {}.", created_role.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(created_role)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/groups/{group_id}/roles", axum::routing::get(handle_list_roles_request))
    .route("/groups/{group_id}/roles", axum::routing::post(handle_create_role_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
