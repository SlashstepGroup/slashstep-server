/**
 * 
 * Any functionality for /users/{user_id}/oauth-authorizations should be handled here.
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
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use regex::Regex;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::str::FromStr;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, oauth_authorization::{InitialOAuthAuthorizationProperties, InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer, OAuthAuthorization}, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_app_by_id, get_authenticated_principal, get_json_web_token_private_key, get_resource_hierarchy, get_user_by_id, verify_delegate_permissions, verify_principal_permissions}};


// /// GET /apps
// /// 
// /// Lists apps.
// #[axum::debug_handler]
// async fn handle_list_apps_request(
//   Query(query_parameters): Query<ResourceListQueryParameters>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>
// ) -> Result<ErasedJson, HTTPError> {

//   let resource_hierarchy = vec![(AccessPolicyResourceType::Server, None)];
//   let response = list_resources(
//     Query(query_parameters), 
//     State(state), 
//     Extension(http_transaction), 
//     Extension(authenticated_user), 
//     Extension(authenticated_app), 
//     resource_hierarchy, 
//     ActionLogEntryTargetResourceType::Server, 
//     None, 
//     |query, database_pool, individual_principal| Box::new(App::count(query, database_pool, individual_principal)),
//     |query, database_pool, individual_principal| Box::new(App::list(query, database_pool, individual_principal)),
//     "slashstep.apps.list", 
//     DEFAULT_MAXIMUM_APP_LIST_LIMIT,
//     "apps",
//     "app"
//   ).await;

//   return response;

// }

pub async fn create_regex(string: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<Regex, HTTPError> {

  let regex = match Regex::new(string) {

    Ok(regex) => regex,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create regex: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(regex);

}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOAuthAuthorizationResponseBody {
  pub code: String,
  pub oauth_authorization: OAuthAuthorization,
}

/// POST /users/{user_id}/oauth-authorizations
/// 
/// Creates an OAuth authorization for a user.
#[axum::debug_handler]
async fn handle_create_oauth_authorization_request(
  Path(user_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer>, JsonRejection>
) -> Result<(StatusCode, Json<CreateOAuthAuthorizationResponseBody>), HTTPError> {

  let http_transaction = http_transaction.clone();
  ServerLogEntry::trace("Validating request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let initial_oauth_authorization_properties_json = match body {

    Ok(initial_oauth_authorization_properties_json) => initial_oauth_authorization_properties_json,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  if initial_oauth_authorization_properties_json.code_challenge.is_some() && initial_oauth_authorization_properties_json.code_challenge_method.as_ref().is_none_or(|code_challenge_method| code_challenge_method != "S256") {

    let http_error = HTTPError::BadRequestError(Some("The code challenge method must be \"S256\" if a code challenge is provided.".to_string()));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  // Verify the scope.
  let full_string_regex = create_regex(r"^(?: ?(?P<action_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(?P<maximum_permission_level>None|User|Editor|Admin))+$", &http_transaction, &state.database_pool).await?;
  let scope = initial_oauth_authorization_properties_json.scope.clone();

  if !full_string_regex.is_match(&scope) {

    let http_error = HTTPError::BadRequestError(Some("The scope must be a space-separated list of action IDs and permission levels.".to_string()));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  // Make sure each action ID and permission level is valid.
  let capture_string_regex = create_regex(r"(?: ?(?P<action_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(?P<maximum_permission_level>None|User|Editor|Admin))", &http_transaction, &state.database_pool).await?;
  for captures in capture_string_regex.captures_iter(&scope) {

    let action_id = match captures.name("action_id") {

      Some(action_id) => match Uuid::parse_str(action_id.as_str()) {

        Ok(action_id) => action_id,

        Err(_) => {

          let http_error = HTTPError::BadRequestError(Some(format!("The action ID \"{}\" is not a valid UUID. Check your scope string.", action_id.as_str())));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
          return Err(http_error);

        }

      },

      None => {

        let http_error = HTTPError::BadRequestError(Some("The scope must be a space-separated list of action IDs and permission levels.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    match captures.name("maximum_permission_level") {

      Some(maximum_permission_level) => match ActionPermissionLevel::from_str(maximum_permission_level.as_str()) {

        Ok(maximum_permission_level) => maximum_permission_level,

        Err(_) => {

          let http_error = HTTPError::BadRequestError(Some(format!("The maximum permission level \"{}\" is not valid. Check your scope string.", maximum_permission_level.as_str())));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
          return Err(http_error);

        }

      },

      None => {

        let http_error = HTTPError::BadRequestError(Some("The scope must be a space-separated list of action IDs and permission levels.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    get_action_by_id(action_id.to_string().as_str(), &http_transaction, &state.database_pool).await?;

  }
  
  // Make sure the user can create access policies for the target action.
  let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_user, &AccessPolicyResourceType::User, &target_user.id, &http_transaction, &state.database_pool).await?;
  let create_oauth_authorizations_action = get_action_by_name("slashstep.oauthAuthorizations.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_oauth_authorizations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_oauth_authorizations_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_app = get_app_by_id(&initial_oauth_authorization_properties_json.app_id.to_string(), &http_transaction, &state.database_pool).await?;
  let authorize_app_action = get_action_by_name("slashstep.apps.authorize", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &authorize_app_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &authorize_app_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the action.
  ServerLogEntry::trace(&format!("Creating OAuth authorization for user {}...", target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let created_oauth_authorization = match OAuthAuthorization::create(&InitialOAuthAuthorizationProperties {
    app_id: target_app.id,
    authorizing_user_id: target_user.id.clone(),
    code_challenge: initial_oauth_authorization_properties_json.code_challenge.clone(),
    scope: initial_oauth_authorization_properties_json.scope.clone(),
    redirect_uri: initial_oauth_authorization_properties_json.redirect_uri.clone(),
    code_challenge_method: initial_oauth_authorization_properties_json.code_challenge_method.clone(),
    state: initial_oauth_authorization_properties_json.state.clone(),
    usage_date: None
  }, &state.database_pool).await {

    Ok(created_oauth_authorization) => created_oauth_authorization,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create OAuth authorization: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  ServerLogEntry::trace("Generating OAuth authorization code...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let jwt_private_key = get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?;
  let authorization_code = match created_oauth_authorization.generate_authorization_code(&jwt_private_key) {

    Ok(authorization_code) => authorization_code,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to generate OAuth authorization code: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: authorize_app_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_oauth_authorizations_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::OAuthAuthorization,
    target_oauth_authorization_id: Some(created_oauth_authorization.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created OAuth authorization {}.", created_oauth_authorization.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let response_body = CreateOAuthAuthorizationResponseBody {
    oauth_authorization: created_oauth_authorization,
    code: authorization_code
  };
  return Ok((StatusCode::CREATED, Json(response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/users/{user_id}/oauth-authorizations", axum::routing::post(handle_create_oauth_authorization_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}