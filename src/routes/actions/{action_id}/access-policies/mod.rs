use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyPrincipalType, AccessPolicyResourceType, InitialAccessPolicyProperties}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{get_action_from_id, get_action_from_name, get_resource_hierarchy_for_action, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct InitialAccessPolicyPropertiesForAction {
  action_id: Uuid,
  permission_level: AccessPolicyPermissionLevel,
  is_inheritance_enabled: bool,
  principal_type: AccessPolicyPrincipalType,
  principal_user_id: Option<Uuid>,
  principal_group_id: Option<Uuid>,
  principal_role_id: Option<Uuid>,
  principal_app_id: Option<Uuid>
}

#[axum::debug_handler]
async fn handle_post_request(
  Path(action_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>,
  body: Result<Json<InitialAccessPolicyPropertiesForAction>, JsonRejection>
) -> Result<Json<AccessPolicy>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;

  // Verify the request body.
  let _ = ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &mut postgres_client).await;
  let access_policy_properties_json = match body {

    Ok(access_policy_properties_json) => access_policy_properties_json,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  // Make sure the user can create access policies for the target action.
  let target_action = get_action_from_id(&action_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy_for_action(&target_action, &http_transaction, &mut postgres_client).await?;
  let update_access_policy_action = get_action_from_name("slashstep.accessPolicies.create", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &update_access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;

  // Make sure the user has at least editor access to the access policy's action.
  let access_policy_action = get_action_from_id(&access_policy_properties_json.action_id.to_string(), &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &access_policy_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::Editor, &mut postgres_client).await?;

  // Create the access policy.
  let _ = ServerLogEntry::trace(&format!("Creating access policy for action {}...", action_id), Some(&http_transaction.id), &mut postgres_client).await;
  let access_policy = match AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: access_policy_properties_json.action_id,
    permission_level: access_policy_properties_json.permission_level,
    is_inheritance_enabled: access_policy_properties_json.is_inheritance_enabled,
    principal_type: access_policy_properties_json.principal_type,
    principal_user_id: access_policy_properties_json.principal_user_id,
    principal_group_id: access_policy_properties_json.principal_group_id,
    principal_role_id: access_policy_properties_json.principal_role_id,
    principal_app_id: access_policy_properties_json.principal_app_id,
    scoped_resource_type: AccessPolicyResourceType::Action,
    scoped_action_id: Some(target_action.id),
    ..Default::default()
  }, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create access policy: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error)

    }

  };

  let _ = ServerLogEntry::success(&format!("Successfully created access policy {}.", access_policy.id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(access_policy));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/actions/{action_id}/access-policies", axum::routing::post(handle_post_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;