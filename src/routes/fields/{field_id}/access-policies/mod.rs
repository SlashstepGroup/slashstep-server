/**
 * 
 * Any functionality for /fields/{field_id}/access-policies should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, access_policy::{AccessPolicy, ResourceType, ActionPermissionLevel, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::{route_handler_utilities::{AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp, get_field_by_id, get_authenticated_principal, get_individual_principal_from_authenticated_principal, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}}};

#[cfg(test)]
mod tests;

/// GET /fields/{field_id}/access-policies
/// 
/// Lists access policies for an field.
#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Path(field_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<AccessPolicy>>), HTTPError> {

  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;

  // Make sure the principal has access to list resources.
  let list_resources_action = get_action_by_name("accessPolicies.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  let resource_hierarchy = get_resource_hierarchy(&field, &ResourceType::Field, &field_id, &http_transaction, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &list_resources_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);

  let query = format!(
    "scoped_resource_type = 'Field' AND scoped_field_id = {}{}", 
    quote_literal(&field_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  let queried_resources = match AccessPolicy::list(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "access policies"),

        ResourceError::PostgresError(error) => match_db_error(&error, "access policies"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list access policies: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting access policies..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match AccessPolicy::count(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count access policies: {:?}", error)));
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
    target_resource_type: ActionLogEntryTargetResourceType::Field,
    target_field_id: Some(field_id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "access policy" } else { "access policies" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<AccessPolicy> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /fields/{field_id}/access-policies
/// 
/// Creates an access policy for an field.
#[axum::debug_handler]
async fn handle_create_access_policy_request(
  Path(field_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialAccessPolicyPropertiesForPredefinedScope>, JsonRejection>
) -> Result<(StatusCode, Json<AccessPolicy>), HTTPError> {

  let field_id = get_uuid_from_string(&field_id, "field", &http_transaction, &state.database_pool).await?;
  let access_policy_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  // Make sure the authenticated_user can create access policies for the target field.
  let target_field = get_field_by_id(&field_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_field, &ResourceType::Field, &target_field.id, &http_transaction, &state.database_pool).await?;
  let create_access_policies_action = get_action_by_name("accessPolicies.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_access_policies_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_access_policies_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Make sure the authenticated_user has at least editor access to the access policy's action.
  let access_policy_action = get_action_by_id(&access_policy_properties_json.action_id, &http_transaction, &state.database_pool).await?;
  let minimum_permission_level = if access_policy_properties_json.permission_level > ActionPermissionLevel::Editor { access_policy_properties_json.permission_level } else { ActionPermissionLevel::Editor };
  verify_principal_permissions(&authenticated_principal, &access_policy_action, &resource_hierarchy, &http_transaction, &minimum_permission_level, &state.database_pool).await?;

  // Create the access policy.
  ServerLogEntry::trace(&format!("Creating access policy for field {}...", field_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let access_policy = match AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: access_policy_properties_json.action_id,
    permission_level: access_policy_properties_json.permission_level,
    is_inheritance_enabled: access_policy_properties_json.is_inheritance_enabled,
    principal_type: access_policy_properties_json.principal_type,
    principal_user_id: access_policy_properties_json.principal_user_id,
    principal_group_id: access_policy_properties_json.principal_group_id,
    principal_role_id: access_policy_properties_json.principal_role_id,
    principal_app_id: access_policy_properties_json.principal_app_id,
    scoped_resource_type: ResourceType::Field,
    scoped_field_id: Some(target_field.id),
    ..Default::default()
  }, &state.database_pool).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create access policy: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_access_policies_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
    target_access_policy_id: Some(access_policy.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created access policy {}.", access_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(access_policy)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/fields/{field_id}/access-policies", axum::routing::get(handle_list_access_policies_request))
    .route("/fields/{field_id}/access-policies", axum::routing::post(handle_create_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}