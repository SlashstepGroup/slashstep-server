/**
 * 
 * Any functionality for /fields/{field_id}/field-choices should be handled here.
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
use chrono::{DateTime, Utc};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, StakeholderType, access_policy::{ResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, field_choice::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, FieldChoice, FieldChoiceType, InitialFieldChoiceProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_field_by_id, get_request_body_without_json_rejection, get_uuid_from_string, match_db_error, match_slashstepql_error, validate_decimal_is_within_range, validate_field_length, verify_delegate_permissions, verify_principal_permissions}};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitialFieldChoicePropertiesWithPredefinedFieldID {

  /// The field choice's description, if applicable.
  pub description: Option<String>,

  /// The field choice's type.
  pub value_type: FieldChoiceType,

  /// The field choice's text value, if applicable.
  pub text_value: Option<String>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The field choice's date time value, if applicable.
  pub timestamp_value: Option<DateTime<Utc>>,

  /// The field choice's stakeholder type, if applicable.
  pub stakeholder_type: Option<StakeholderType>,

  /// The field choice's stakeholder user ID, if applicable.
  pub stakeholder_user_id: Option<Uuid>,

  /// The field choice's stakeholder group ID, if applicable.
  pub stakeholder_group_id: Option<Uuid>,

  /// The field choice's stakeholder app ID, if applicable.
  pub stakeholder_app_id: Option<Uuid>

}

/// GET /fields/{field_id}/field-choices
/// 
/// Lists field choices for an app.
#[axum::debug_handler]
pub async fn handle_list_field_choices_request(
  Path(field_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<FieldChoice>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("fieldChoices.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_field, &ResourceType::Field, &target_field.id, &http_transaction, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &list_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "field_id = {}{}", 
    quote_literal(&field_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  let queried_resources = match FieldChoice::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "field choices"),

        ResourceError::PostgresError(error) => match_db_error(&error, "field choices"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list field choices: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting field choices..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match FieldChoice::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count field choices: {:?}", error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::Field,
    target_field_id: Some(target_field.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "field choice" } else { "field choices" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<FieldChoice> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /fields/{field_id}/field-choices
/// 
/// Creates an field choice for an app.
#[axum::debug_handler]
async fn handle_create_field_choice_request(
  Path(field_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialFieldChoicePropertiesWithPredefinedFieldID>, JsonRejection>
) -> Result<(StatusCode, Json<FieldChoice>), HTTPError> {

  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let field_choice_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(field_choice_text_value) = &field_choice_properties_json.text_value { 

    validate_field_length(field_choice_text_value, "fieldValues.maximumTextValueLength", "text_value", &http_transaction, &state.database_pool).await?;

  }
  if let Some(field_choice_number_value) = &field_choice_properties_json.number_value {

    validate_decimal_is_within_range(field_choice_number_value, "fieldValues.minimumNumberValue", "fieldValues.maximumNumberValue", "number_value", &http_transaction, &state.database_pool).await?;

  }
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_field, &ResourceType::Field, &target_field.id, &http_transaction, &state.database_pool).await?;
  let create_field_choices_action = get_action_by_name("fieldChoices.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_field_choices_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &create_field_choices_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the authenticated field choice.
  ServerLogEntry::trace(&format!("Creating field choice for field {}...", target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let created_field_choice = match FieldChoice::create(&InitialFieldChoiceProperties {
    field_id: target_field.id,
    description: field_choice_properties_json.description.clone(),
    value_type: field_choice_properties_json.value_type.clone(),
    text_value: field_choice_properties_json.text_value.clone(),
    number_value: field_choice_properties_json.number_value,
    timestamp_value: field_choice_properties_json.timestamp_value,
    stakeholder_type: field_choice_properties_json.stakeholder_type.clone(),
    stakeholder_user_id: field_choice_properties_json.stakeholder_user_id,
    stakeholder_group_id: field_choice_properties_json.stakeholder_group_id,
    stakeholder_app_id: field_choice_properties_json.stakeholder_app_id
  }, &state.database_pool).await {

    Ok(created_field_choice) => created_field_choice,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create field choice: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_field_choices_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::FieldChoice,
    target_field_choice_id: Some(created_field_choice.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created field choice {}.", created_field_choice.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(created_field_choice)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/fields/{field_id}/field-choices", axum::routing::get(handle_list_field_choices_request))
    .route("/fields/{field_id}/field-choices", axum::routing::post(handle_create_field_choice_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
