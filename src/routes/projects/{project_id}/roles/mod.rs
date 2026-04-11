/**
 * 
 * Any functionality for /projects/{project_id}/roles should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, ResourceType, access_policy::ActionPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, role::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialRoleProperties, InitialRolePropertiesWithPredefinedParent, Role, RoleParentResourceType}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_project_by_id, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, validate_field_length, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}};

/// GET /projects/{project_id}/roles
/// 
/// Lists roles for a project.
#[axum::debug_handler]
async fn handle_list_roles_request(
  Path(project_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Role>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("roles.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_project_id = {}{}", 
    quote_literal(&project_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND ({})", query))).unwrap_or("".to_string())
  );
  let queried_resources = match Role::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "roles"),

        ResourceError::PostgresError(error) => match_db_error(&error, "roles"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list roles: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting roles..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Role::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count roles: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Project,
    target_project_id: Some(project_id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "role" } else { "roles" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Role> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /projects/{project_id}/roles
/// 
/// Creates a role for an project.
#[axum::debug_handler]
async fn handle_create_role_request(
  Path(project_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialRolePropertiesWithPredefinedParent>, JsonRejection>
) -> Result<(StatusCode, Json<Role>), HTTPError> {

  // Make sure the user can create roles for the target action.
  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let role_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  validate_field_length(&role_properties_json.name, "roles.maximumNameLength", "name", &http_transaction, &state.database_pool).await?;
  validate_resource_name(&role_properties_json.name, "roles.allowedNameRegex", "role", &http_transaction, &state.database_pool).await?;
  validate_field_length(&role_properties_json.display_name, "roles.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;
  if let Some(role_description) = &role_properties_json.description {

    validate_field_length(role_description, "roles.maximumDescriptionLength", "description", &http_transaction, &state.database_pool).await?;

  }
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let create_roles_action = get_action_by_name("roles.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_roles_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &create_roles_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the role.
  ServerLogEntry::trace(&format!("Creating role for project {}...", project_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let role = match Role::create(&InitialRoleProperties {
    name: role_properties_json.name.clone(),
    display_name: role_properties_json.display_name.clone(),
    description: role_properties_json.description.clone(),
    parent_resource_type: RoleParentResourceType::Project,
    parent_project_id: Some(target_project.id),
    parent_group_id: None,
    parent_workspace_id: None,
    protected_role_type: None
  }, &state.database_pool).await {

    Ok(role) => role,

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
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Role,
    target_role_id: Some(role.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created role {}.", role.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(role)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/projects/{project_id}/roles", axum::routing::get(handle_list_roles_request))
    .route("/projects/{project_id}/roles", axum::routing::post(handle_create_role_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
