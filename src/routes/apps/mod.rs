/**
 * 
 * Any functionality for /apps should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./{app_id}/mod.rs"]
mod app_id;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use argon2::{Argon2, PasswordHasher, password_hash::{SaltString, rand_core::{OsRng, le}}};
use axum::{Extension, Json, Router, extract::{Query, State, rejection::JsonRejection}};
use axum_extra::response::ErasedJson;
use rand::{Rng, RngExt, distr::Alphanumeric};
use reqwest::StatusCode;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{ResourceError, access_policy::{AccessPolicyResourceType, ActionPermissionLevel, ResourceHierarchy}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, AppClientType, AppParentResourceType, DEFAULT_MAXIMUM_APP_LIST_LIMIT, InitialAppProperties}, app_authorization::AppAuthorization, configuration::Configuration, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_configuration_by_name, get_request_body_without_json_rejection, verify_delegate_permissions, verify_principal_permissions}}};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct InitialAppPropertiesWithoutClientSecretHash {
  pub name: String,
  pub display_name: String,
  pub description: Option<String>,
  pub client_type: AppClientType,
  pub parent_resource_type: AppParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_user_id: Option<Uuid>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppWithClientSecret {
  pub id: Uuid,
  pub name: String,
  pub display_name: String,
  pub description: Option<String>,
  pub client_type: AppClientType,
  pub client_secret: Option<String>,
  pub parent_resource_type: AppParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_user_id: Option<Uuid>
}

pub async fn validate_app_name(name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let allowed_name_regex_configuration = get_configuration_by_name("apps.allowedNameRegex", http_transaction, database_pool).await?;
  let allowed_name_regex_string = match allowed_name_regex_configuration.text_value.or(allowed_name_regex_configuration.default_text_value) {

    Some(allowed_name_regex_string) => allowed_name_regex_string,

    None => {

      ServerLogEntry::warning("Missing value and default value for configuration apps.allowedNameRegex. Using default regex pattern that allows any non-empty string as an app name. Consider setting a restrictive regex pattern in the configuration for better security.", Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace("Creating regex for validating app names...", Some(&http_transaction.id), database_pool).await.ok();
  let regex = match regex::Regex::new(&allowed_name_regex_string) {

    Ok(regex) => regex,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create regex for validating app names: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
      return Err(http_error)

    }

  };

  ServerLogEntry::trace("Validating app name against regex...", Some(&http_transaction.id), database_pool).await.ok();
  if !regex.is_match(name) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("App names must match the allowed pattern: {}", allowed_name_regex_string)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  Ok(())

}

pub async fn validate_app_display_name(name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let allowed_display_name_regex_configuration = get_configuration_by_name("apps.allowedDisplayNameRegex", http_transaction, database_pool).await?;
  let allowed_display_name_regex_string = match allowed_display_name_regex_configuration.text_value.or(allowed_display_name_regex_configuration.default_text_value) {

    Some(allowed_display_name_regex_string) => allowed_display_name_regex_string,

    None => {

      ServerLogEntry::warning("Missing value and default value for configuration apps.allowedDisplayNameRegex. Consider setting a regex pattern in the configuration for better security.", Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace("Creating regex for validating app display names...", Some(&http_transaction.id), database_pool).await.ok();
  let regex = match regex::Regex::new(&allowed_display_name_regex_string) {

    Ok(regex) => regex,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create regex for validating app display names: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
      return Err(http_error)

    }

  };

  ServerLogEntry::trace("Validating app display name against regex...", Some(&http_transaction.id), database_pool).await.ok();
  if !regex.is_match(name) {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("App display names must match the allowed pattern: {}", allowed_display_name_regex_string)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }

  Ok(())

}

pub async fn validate_app_display_name_length(display_name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let maximum_display_name_length_configuration = get_configuration_by_name("apps.maximumDisplayNameLength", http_transaction, database_pool).await?;
  let maximum_display_name_length = match maximum_display_name_length_configuration.number_value.or(maximum_display_name_length_configuration.default_number_value) {

    Some(maximum_display_name_length) => match maximum_display_name_length.to_usize() {

      Some(maximum_display_name_length) => maximum_display_name_length,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Invalid number value for configuration apps.maximumDisplayNameLength. The value must be a positive integer that can be represented as a usize.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
        return Err(http_error);

      }

    },

    None => {

      ServerLogEntry::warning("Missing value and default value for configuration apps.maximumDisplayNameLength. This is a security risk. Consider setting a restrictive maximum display name length in the configuration.", Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace("Validating app display name length...", Some(&http_transaction.id), database_pool).await.ok();
  if display_name.len() > maximum_display_name_length {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("App display names must be at most {} characters long.", maximum_display_name_length)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }
  

  Ok(())

}

pub async fn validate_app_name_length(name: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  let maximum_name_length_configuration = get_configuration_by_name("apps.maximumNameLength", http_transaction, database_pool).await?;
  let maximum_name_length = match maximum_name_length_configuration.number_value.or(maximum_name_length_configuration.default_number_value) {

    Some(maximum_name_length) => match maximum_name_length.to_usize() {

      Some(maximum_name_length) => maximum_name_length,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Invalid number value for configuration apps.maximumNameLength. The value must be a positive integer that can be represented as a usize.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
        return Err(http_error);

      }

    },

    None => {

      ServerLogEntry::warning("Missing value and default value for configuration apps.maximumNameLength. This is a security risk. Consider setting a restrictive maximum name length in the configuration.", Some(&http_transaction.id), database_pool).await.ok();
      return Ok(());

    }

  };

  ServerLogEntry::trace("Validating app name length...", Some(&http_transaction.id), database_pool).await.ok();
  if name.len() > maximum_name_length {

    let http_error = HTTPError::UnprocessableEntity(Some(format!("App names must be at most {} characters long.", maximum_name_length)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
    return Err(http_error);

  }
  

  Ok(())

}

/// GET /apps
/// 
/// Lists apps.
#[axum::debug_handler]
async fn handle_list_apps_request(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  let resource_hierarchy = vec![(AccessPolicyResourceType::Server, None)];
  let response = list_resources(
    Query(query_parameters), 
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    resource_hierarchy, 
    ActionLogEntryTargetResourceType::Server, 
    None, 
    |query, database_pool, individual_principal| Box::new(App::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(App::list(query, database_pool, individual_principal)),
    "apps.list", 
    DEFAULT_MAXIMUM_APP_LIST_LIMIT,
    "apps",
    "app"
  ).await;

  return response;

}

/// POST /apps
/// 
/// Creates an app on the server level.
#[axum::debug_handler]
async fn handle_create_app_request(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialAppPropertiesWithoutClientSecretHash>, JsonRejection>
) -> Result<(StatusCode, Json<AppWithClientSecret>), HTTPError> {

  let http_transaction = http_transaction.clone();
  let app_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  validate_app_name(&app_properties_json.name, &http_transaction, &state.database_pool).await?;
  validate_app_name_length(&app_properties_json.name, &http_transaction, &state.database_pool).await?;
  validate_app_display_name(&app_properties_json.display_name, &http_transaction, &state.database_pool).await?;
  validate_app_display_name_length(&app_properties_json.display_name, &http_transaction, &state.database_pool).await?;

  // Make sure the authenticated_user can create apps for the target action log entry.
  let resource_hierarchy: ResourceHierarchy = vec![(AccessPolicyResourceType::Server, None)];
  let create_apps_action = get_action_by_name("apps.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_apps_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_apps_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let mut client_secret_hash = None;
  let mut client_secret = None;
  if app_properties_json.client_type == AppClientType::Confidential {

    ServerLogEntry::trace("Generating client secret for confidential app...", Some(&http_transaction.id), &state.database_pool).await.ok();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let some_client_secret = rand::rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect::<String>();
    client_secret = Some(some_client_secret.clone());
    client_secret_hash = match argon2.hash_password(some_client_secret.as_bytes(), &salt) {

      Ok(hash) => Some(hash.to_string()),

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to hash client secret: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

  }

  // Create the app.
  ServerLogEntry::trace("Creating app for server...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let app = match App::create(&InitialAppProperties {
    name: app_properties_json.name.clone(),
    display_name: app_properties_json.display_name.clone(),
    description: app_properties_json.description.clone(),
    parent_resource_type: AppParentResourceType::Server,
    client_type: app_properties_json.client_type.clone(),
    client_secret_hash,
    ..Default::default()
  }, &state.database_pool).await {

    Ok(app) => app,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create app: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created app {}.", app.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(AppWithClientSecret {
    id: app.id,
    name: app.name,
    display_name: app.display_name,
    description: app.description,
    client_type: app.client_type,
    client_secret,
    parent_resource_type: app.parent_resource_type,
    parent_workspace_id: app.parent_workspace_id,
    parent_user_id: app.parent_user_id
  })));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps", axum::routing::get(handle_list_apps_request))
    .route("/apps", axum::routing::post(handle_create_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .merge(app_id::get_router(state.clone()));
  return router;

}