/**
 * 
 * Any functionality for /configurations/{configuration_id}/access-policies should be handled here.
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
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::{AccessPolicy, AccessPolicyResourceType, ActionPermissionLevel, DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_authenticated_principal, get_configuration_by_id, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /configurations/{configuration_id}/access-policies
/// 
/// Lists access policies for an configuration.
#[axum::debug_handler]
async fn handle_list_access_policies_request(
  Path(configuration_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let configuration_id = get_uuid_from_string(&configuration_id, "configuration", &http_transaction, &state.database_pool).await?;
  let configuration = get_configuration_by_id(&configuration_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&configuration, &AccessPolicyResourceType::Configuration, &configuration.id, &http_transaction, &state.database_pool).await?;

  let query = format!(
    "scoped_resource_type = 'Configuration' AND scoped_configuration_id = {}{}",
    quote_literal(&configuration.id.to_string()), 
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
    ActionLogEntryTargetResourceType::Configuration, 
    Some(configuration.id), 
    |query, database_pool, individual_principal| Box::new(AccessPolicy::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(AccessPolicy::list(query, database_pool, individual_principal)),
    "slashstep.accessPolicies.list", 
    DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT,
    "access policies",
    "access policy"
  ).await;
  
  return response;

}

// /// POST /configurations/{configuration_id}/access-policies
// /// 
// /// Creates an access policy for an configuration.
// #[axum::debug_handler]
// async fn handle_create_access_policy_request(
//   Path(configuration_id): Path<String>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>,
//   Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
//   body: Result<Json<InitialAccessPolicyPropertiesForPredefinedScope>, JsonRejection>
// ) -> Result<Json<AccessPolicy>, HTTPError> {

//   let http_transaction = http_transaction.clone();

//   // Verify the request body.
//   ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
//   let access_policy_properties_json = match body {

//     Ok(access_policy_properties_json) => access_policy_properties_json,

//     Err(error) => {

//       let http_error = match error {

//         JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

//         JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

//         JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

//         JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

//         _ => HTTPError::InternalServerError(Some(error.to_string()))

//       };
      
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   };

//   // Make sure the user can create access policies for the target action.
//   let target_configuration = get_configuration_by_id(&configuration_id, &http_transaction, &state.database_pool).await?;
//   let resource_hierarchy = get_resource_hierarchy(&target_configuration, &AccessPolicyResourceType::Configuration, &target_configuration.id, &http_transaction, &state.database_pool).await?;
//   let create_access_policies_action = get_action_by_name("slashstep.accessPolicies.create", &http_transaction, &state.database_pool).await?;
//   verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_access_policies_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
//   let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
//   verify_principal_permissions(&authenticated_principal, &create_access_policies_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

//   // Make sure the user has at least editor access to the access policy's action.
//   let access_policy_action = get_action_by_id(&access_policy_properties_json.action_id.to_string(), &http_transaction, &state.database_pool).await?;
//   let minimum_permission_level = if access_policy_properties_json.permission_level > ActionPermissionLevel::Editor { access_policy_properties_json.permission_level } else { ActionPermissionLevel::Editor };
//   verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &access_policy_action.id, &http_transaction.id, &minimum_permission_level, &state.database_pool).await?;
//   verify_principal_permissions(&authenticated_principal, &access_policy_action, &resource_hierarchy, &http_transaction, &minimum_permission_level, &state.database_pool).await?;

//   // Create the access policy.
//   ServerLogEntry::trace(&format!("Creating access policy for configuration {}...", configuration_id), Some(&http_transaction.id), &state.database_pool).await.ok();
//   let access_policy = match AccessPolicy::create(&InitialAccessPolicyProperties {
//     action_id: access_policy_properties_json.action_id,
//     permission_level: access_policy_properties_json.permission_level,
//     is_inheritance_enabled: access_policy_properties_json.is_inheritance_enabled,
//     principal_type: access_policy_properties_json.principal_type,
//     principal_user_id: access_policy_properties_json.principal_user_id,
//     principal_group_id: access_policy_properties_json.principal_group_id,
//     principal_role_id: access_policy_properties_json.principal_role_id,
//     principal_app_id: access_policy_properties_json.principal_app_id,
//     scoped_resource_type: AccessPolicyResourceType::Configuration,
//     scoped_configuration_id: Some(target_configuration.id),
//     ..Default::default()
//   }, &state.database_pool).await {

//     Ok(access_policy) => access_policy,

//     Err(error) => {

//       let http_error = HTTPError::InternalServerError(Some(format!("Failed to create access policy: {:?}", error)));
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error)

//     }

//   };

//   ActionLogEntry::create(&InitialActionLogEntryProperties {
//     action_id: create_access_policies_action.id,
//     http_transaction_id: Some(http_transaction.id),
//     actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
//     actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
//     actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
//     target_resource_type: ActionLogEntryTargetResourceType::AccessPolicy,
//     target_access_policy_id: Some(access_policy.id),
//     ..Default::default()
//   }, &state.database_pool).await.ok();
//   ServerLogEntry::success(&format!("Successfully created access policy {}.", access_policy.id), Some(&http_transaction.id), &state.database_pool).await.ok();

//   return Ok(Json(access_policy));

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/configurations/{configuration_id}/access-policies", axum::routing::get(handle_list_access_policies_request))
    // .route("/configurations/{configuration_id}/access-policies", axum::routing::post(handle_create_access_policy_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}
