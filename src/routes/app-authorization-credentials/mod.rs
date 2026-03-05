/**
 * 
 * Any functionality for /app-authorization-credentials should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./{app_authorization_credential_id}/mod.rs"]
mod app_authorization_credential_id;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{Extension, Json, Router, extract::{Query, State}};
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, access_policy::{ResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, app_authorization_credential::{AppAuthorizationCredential, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::{resource_hierarchy::ResourceHierarchy, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_individual_principal_from_authenticated_principal, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /app-authorization-credentials
/// 
/// Lists app authorization credentials.
#[axum::debug_handler]
async fn handle_list_app_authorization_credentials_request(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<AppAuthorizationCredential>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let list_resources_action = get_action_by_name("appAuthorizationCredentials.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  let resource_hierarchy: ResourceHierarchy = vec![(ResourceType::Server, None)];
  verify_principal_permissions(&authenticated_principal, &list_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);

  ServerLogEntry::trace("Listing app authorization credentials...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let query = query_parameters.query.unwrap_or("".to_string());
  let queried_resources = match AppAuthorizationCredential::list(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "app authorization credentials"),

        ResourceError::PostgresError(error) => match_db_error(&error, "app authorization credentials"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list app authorization credentials: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting app authorization credentials..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match AppAuthorizationCredential::count(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count app authorization credentials: {:?}", error)));
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
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Server,
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_app_authorization_credential_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_app_authorization_credential_list_length, if queried_app_authorization_credential_list_length == 1 { "app authorization credential" } else { "app authorization credentials" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<AppAuthorizationCredential> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/app-authorization-credentials", axum::routing::get(handle_list_app_authorization_credentials_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(app_authorization_credential_id::get_router(state.clone()));
  return router;

}