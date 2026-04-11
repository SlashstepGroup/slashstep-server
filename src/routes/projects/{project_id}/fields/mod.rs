/**
 * 
 * Any functionality for /projects/{project_id}/fields should be handled here.
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
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, ResourceType, access_policy::ActionPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, field::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialFieldProperties, InitialFieldPropertiesWithPredefinedParent, Field}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_project_by_id, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, validate_field_length, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}};

/// GET /projects/{project_id}/fields
/// 
/// Lists fields for a project.
#[axum::debug_handler]
async fn handle_list_fields_request(
  Path(project_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Field>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("fields.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_project_id = {}{}", 
    quote_literal(&project_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND ({})", query))).unwrap_or("".to_string())
  );
  let queried_resources = match Field::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "fields"),

        ResourceError::PostgresError(error) => match_db_error(&error, "fields"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list fields: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting fields..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Field::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count fields: {:?}", error)));
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
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "field" } else { "fields" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Field> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /projects/{project_id}/fields
/// 
/// Creates a field for an project.
#[axum::debug_handler]
async fn handle_create_field_request(
  Path(project_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialFieldPropertiesWithPredefinedParent>, JsonRejection>
) -> Result<(StatusCode, Json<Field>), HTTPError> {

  // Make sure the user can create fields for the target action.
  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let field_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  validate_field_length(&field_properties_json.name, "fields.maximumNameLength", "name", &http_transaction, &state.database_pool).await?;
  validate_resource_name(&field_properties_json.name, "fields.allowedNameRegex", "field", &http_transaction, &state.database_pool).await?;
  validate_field_length(&field_properties_json.display_name, "fields.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;
  if let Some(field_description) = &field_properties_json.description {

    validate_field_length(field_description, "fields.maximumDescriptionLength", "description", &http_transaction, &state.database_pool).await?;

  }
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let create_fields_action = get_action_by_name("fields.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_fields_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &create_fields_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the field.
  ServerLogEntry::trace(&format!("Creating field for project {}...", project_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let field = match Field::create(&InitialFieldProperties {
    name: field_properties_json.name.clone(),
    display_name: field_properties_json.display_name.clone(),
    description: field_properties_json.description.clone(),
    field_value_type: field_properties_json.field_value_type.clone(),
    minimum_value: field_properties_json.minimum_value.clone(),
    maximum_value: field_properties_json.maximum_value.clone(),
    minimum_choice_count: field_properties_json.minimum_choice_count.clone(),
    maximum_choice_count: field_properties_json.maximum_choice_count.clone(),
    parent_project_id: project_id,
    is_deadline: field_properties_json.is_deadline
  }, &state.database_pool).await {

    Ok(field) => field,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create field: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_fields_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Field,
    target_field_id: Some(field.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created field {}.", field.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(field)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/projects/{project_id}/fields", axum::routing::get(handle_list_fields_request))
    .route("/projects/{project_id}/fields", axum::routing::post(handle_create_field_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
