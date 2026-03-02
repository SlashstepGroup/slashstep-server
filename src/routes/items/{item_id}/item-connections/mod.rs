/**
 * 
 * Any functionality for /items/{item_id}/item-connections should be handled here.
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
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, item_connection::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, ItemConnection, ItemConnectionParentResourceType, InitialItemConnectionProperties, InitialItemConnectionPropertiesWithPredefinedParent}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_field_by_id, get_item_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, validate_decimal_is_within_range, validate_field_length, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /items/{item_id}/item-connections
/// 
/// Lists item connections for an item.
#[axum::debug_handler]
async fn handle_list_item_connections_request(
  Path(item_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
  let target_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_item, &AccessPolicyResourceType::Item, &target_item.id, &http_transaction, &state.database_pool).await?;

  let query = format!(
    "parent_resource_type = 'Item' AND parent_item_id = {}{}", 
    quote_literal(&target_item.id.to_string()), 
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
    ActionLogEntryTargetResourceType::Item, 
    Some(target_item.id), 
    |query, database_pool, individual_principal| Box::new(ItemConnection::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(ItemConnection::list(query, database_pool, individual_principal)),
    "itemConnections.list", 
    DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
    "item connections",
    "item connection"
  ).await;
  
  return response;

}

/// POST /items/{item_id}/item-connections
/// 
/// Creates a item connection for an item.
#[axum::debug_handler]
async fn handle_create_item_connection_request(
  Path(item_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialItemConnectionPropertiesWithPredefinedParent>, JsonRejection>
) -> Result<(StatusCode, Json<ItemConnection>), HTTPError> {

  // Make sure the user can create item connections for the target action.
  let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
  let item_connection_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  if let Some(item_connection_text_value) = &item_connection_properties_json.text_value { 

    validate_field_length(item_connection_text_value, "itemConnections.maximumTextValueLength", "text_value", &http_transaction, &state.database_pool).await?;

  }
  if let Some(item_connection_number_value) = &item_connection_properties_json.number_value {

    validate_decimal_is_within_range(item_connection_number_value, "itemConnections.minimumNumberValue", "itemConnections.maximumNumberValue", "number_value", &http_transaction, &state.database_pool).await?;

  }
  let target_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_item, &AccessPolicyResourceType::Item, &target_item.id, &http_transaction, &state.database_pool).await?;
  let create_item_connections_action = get_action_by_name("itemConnections.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_item_connections_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_item_connections_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Verify the field is a part of the same project.
  let field = get_field_by_id(&item_connection_properties_json.field_id, &http_transaction, &state.database_pool).await?;
  if field.parent_project_id != target_item.parent_project_id {

    let http_error = HTTPError::UnprocessableEntity(Some("The specified field is not a part of the same project as the item.".to_string()));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error)

  }

  // Create the item connection.
  ServerLogEntry::trace(&format!("Creating item connection for item {}...", item_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let item_connection = match ItemConnection::create(&InitialItemConnectionProperties {
    field_id: item_connection_properties_json.field_id,
    parent_resource_type: ItemConnectionParentResourceType::Item,
    parent_item_id: Some(target_item.id),
    parent_field_id: None,
    value_type: item_connection_properties_json.value_type,
    text_value: item_connection_properties_json.text_value.clone(),
    number_value: item_connection_properties_json.number_value,
    boolean_value: item_connection_properties_json.boolean_value,
    timestamp_value: item_connection_properties_json.timestamp_value,
    stakeholder_type: item_connection_properties_json.stakeholder_type,
    stakeholder_user_id: item_connection_properties_json.stakeholder_user_id,
    stakeholder_group_id: item_connection_properties_json.stakeholder_group_id,
    stakeholder_app_id: item_connection_properties_json.stakeholder_app_id,
  }, &state.database_pool).await {

    Ok(item_connection) => item_connection,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create item connection: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_item_connections_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnection,
    target_item_connection_id: Some(item_connection.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created item connection {}.", item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(item_connection)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/items/{item_id}/item-connections", axum::routing::get(handle_list_item_connections_request))
    .route("/items/{item_id}/item-connections", axum::routing::post(handle_create_item_connection_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
