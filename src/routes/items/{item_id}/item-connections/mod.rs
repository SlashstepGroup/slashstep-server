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
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, access_policy::{ActionPermissionLevel, ResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, field_value::DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, http_transaction::HTTPTransaction, item_connection::{InitialItemConnectionProperties, InitialItemConnectionPropertiesWithPredefinedOutwardItem, ItemConnection}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_item_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

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
) -> Result<(StatusCode, Json<ListResourcesResponseBody<ItemConnection>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("itemConnections.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Item, Some(&target_item.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "(outward_item_id = {} OR inward_item_id = {}){}", 
    quote_literal(&item_id.to_string()), 
    quote_literal(&item_id.to_string()),
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  let queried_resources = match ItemConnection::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "item connections"),

        ResourceError::PostgresError(error) => match_db_error(&error, "item connections"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list item connections: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting item connections..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match ItemConnection::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count item connections: {:?}", error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::Item,
    target_item_id: Some(item_id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "item connection" } else { "item connections" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<ItemConnection> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /items/{item_id}/item-connections
/// 
/// Creates a item connection for an item. 
/// 
/// The outward item is the item specified in the path, while the 
/// inward item is the item specified in the request body.
#[axum::debug_handler]
async fn handle_create_item_connection_request(
  Path(item_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialItemConnectionPropertiesWithPredefinedOutwardItem>, JsonRejection>
) -> Result<(StatusCode, Json<ItemConnection>), HTTPError> {

  // Make sure the user can create item connections for the target action.
  let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
  let item_connection_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let outward_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
  let inward_item = get_item_by_id(&item_connection_properties_json.inward_item_id, &http_transaction, &state.database_pool).await?;
  let create_item_connections_action = get_action_by_name("itemConnections.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_item_connections_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  if let Err(error) = verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Item, Some(&outward_item.id), &create_item_connections_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await {

    match error {

      HTTPError::ForbiddenError(_) => verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Item, Some(&inward_item.id), &create_item_connections_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?,

      error => return Err(error)

    }

  }

  // Create the item connection.
  ServerLogEntry::trace(&format!("Creating item connection for item {}...", item_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let item_connection = match ItemConnection::create(&InitialItemConnectionProperties {
    item_connection_type_id: item_connection_properties_json.item_connection_type_id,
    inward_item_id: item_connection_properties_json.inward_item_id,
    outward_item_id: item_id
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
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
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
