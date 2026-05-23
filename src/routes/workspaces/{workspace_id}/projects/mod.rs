/**
 * 
 * Any functionality for /workspaces/{workspace_id}/projects should be handled here.
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
use chrono::{DateTime, Utc};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware}, resources::{ResourceError, ResourceType, access_policy::PermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, project::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialProjectProperties, Project}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_workspace_by_id, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, validate_field_length, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}};

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateProjectRequestBody {
  pub name: String,
  pub key: String,
  pub display_name: String,
  pub description: Option<String>,
  pub start_date: Option<DateTime<Utc>>,
  pub end_date: Option<DateTime<Utc>>
}

/// GET /workspaces/{workspace_id}/projects
/// 
/// Lists projects for a workspace.
#[axum::debug_handler]
async fn handle_list_projects_request(
  Path(workspace_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Project>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let workspace_id = get_uuid_from_string(&workspace_id, "workspace", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("projects.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &PermissionLevel::User, &state.database_pool).await?;
  let target_workspace = get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Workspace, Some(&target_workspace.id), &list_resources_action, &http_transaction, &PermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_workspace_id = {}{}", 
    quote_literal(&workspace_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND ({})", query))).unwrap_or("".to_string())
  );
  let queried_resources = match Project::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "projects"),

        ResourceError::PostgresError(error) => match_db_error(&error, "projects"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list projects: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting projects..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Project::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count projects: {:?}", error)));
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
    target_resource_type: ResourceType::Workspace,
    target_workspace_id: Some(workspace_id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "project" } else { "projects" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Project> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /workspaces/{workspace_id}/projects
/// 
/// Creates a project for an workspace.
#[axum::debug_handler]
async fn handle_create_project_request(
  Path(workspace_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<CreateProjectRequestBody>, JsonRejection>
) -> Result<(StatusCode, Json<Project>), HTTPError> {

  // Make sure the user can create projects for the target action.
  let workspace_id = get_uuid_from_string(&workspace_id, "workspace", &http_transaction, &state.database_pool).await?;
  let project_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  validate_field_length(&project_properties_json.name, "projects.maximumNameLength", "name", &http_transaction, &state.database_pool).await?;
  validate_resource_name(&project_properties_json.name, "projects.allowedNameRegex", "project", &http_transaction, &state.database_pool).await?;
  validate_field_length(&project_properties_json.display_name, "projects.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;
  if let Some(project_description) = &project_properties_json.description {

    validate_field_length(project_description, "projects.maximumDescriptionLength", "description", &http_transaction, &state.database_pool).await?;

  }
  let target_workspace = get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
  let create_projects_action = get_action_by_name("projects.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_projects_action.id, &http_transaction.id, &PermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Workspace, Some(&target_workspace.id), &create_projects_action, &http_transaction, &PermissionLevel::User, &state.database_pool).await?;

  // Create the project.
  ServerLogEntry::trace(&format!("Creating project for workspace {}...", workspace_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let project = match Project::create(&InitialProjectProperties {
    name: project_properties_json.name.clone(),
    key: project_properties_json.key.clone(),
    display_name: project_properties_json.display_name.clone(),
    description: project_properties_json.description.clone(),
    start_date: project_properties_json.start_date.clone(),
    end_date: project_properties_json.end_date.clone(),
    parent_workspace_id: target_workspace.id.clone(),
  }, &state.database_pool).await {

    Ok(project) => project,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create project: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_projects_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Project,
    target_project_id: Some(project.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created project {}.", project.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(project)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/workspaces/{workspace_id}/projects", axum::routing::get(handle_list_projects_request))
    .route("/workspaces/{workspace_id}/projects", axum::routing::post(handle_create_project_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit_middleware::verify_total_maximum_rate_limits))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
