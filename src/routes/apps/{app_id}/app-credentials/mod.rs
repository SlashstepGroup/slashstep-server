/**
 * 
 * Any functionality for /apps/{app_id}/app-credentials should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::{net::IpAddr, sync::Arc};
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use axum_extra::response::ErasedJson;
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, ed25519::signature::rand_core::OsRng, pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding}};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_request_middleware}, resources::{ResourceError, access_policy::{AccessPolicyPermissionLevel, AccessPolicyResourceType}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_credential::{AppCredential, DEFAULT_MAXIMUM_APP_CREDENTIAL_LIST_LIMIT, InitialAppCredentialProperties, InitialAppCredentialPropertiesForPredefinedScope}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_from_name, get_app_from_id, get_authenticated_principal, get_individual_principal_from_authenticated_principal, get_resource_hierarchy, match_db_error, match_slashstepql_error, verify_principal_permissions}};

#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize)]
pub struct ListAppCredentialsQueryParameters {
  pub query: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAppCredentialsResponseBody {
  pub app_credentials: Vec<AppCredential>,
  pub total_count: i64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAppCredentialResponseBody {
  pub id: Uuid,
  pub app_id: Uuid,
  pub description: Option<String>,
  pub expiration_date: Option<DateTime<Utc>>,
  pub creation_ip_address: IpAddr,
  pub public_key: String,
  pub private_key: String
}

/// GET /apps/{app_id}/app-credentials
/// 
/// Lists app credentials for an app.
#[axum::debug_handler]
pub async fn handle_list_app_credentials_request(
  Path(app_id): Path<String>,
  Query(query_parameters): Query<ListAppCredentialsQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>
) -> Result<ErasedJson, HTTPError> {

  let http_transaction = http_transaction.clone();
  let target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let list_app_credentials_action = get_action_from_name("slashstep.appCredentials.list", &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &list_app_credentials_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;
  
  let individual_principal = get_individual_principal_from_authenticated_principal(&authenticated_principal);
  let query = query_parameters.query.unwrap_or("".to_string());
  let app_credentials = match AppCredential::list(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(app_credentials) => app_credentials,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_APP_CREDENTIAL_LIST_LIMIT, "authenticated_app credentials"),

        ResourceError::PostgresError(error) => match_db_error(&error, "authenticated_app credentials"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list authenticated_app credentials: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting authenticated_app credentials..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let app_credential_count = match AppCredential::count(&query, &state.database_pool, Some(&individual_principal)).await {

    Ok(app_credential_count) => app_credential_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count authenticated_app credentials: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  // TODO: Use the calling function's resource type and ID instead of referencing the instance.
  // This'll make the log more useful.
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_app_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    reason: None, // TODO: Support reasons.
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully {} returned authenticated_app credentials.", app_credentials.len()), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListAppCredentialsResponseBody {
    app_credentials,
    total_count: app_credential_count
  };

  return Ok(ErasedJson::pretty(&response_body));

}

/// POST /apps/{app_id}/app-credentials
/// 
/// Creates an app credential for an app.
#[axum::debug_handler]
async fn handle_create_app_credential_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  body: Result<Json<InitialAppCredentialPropertiesForPredefinedScope>, JsonRejection>
) -> Result<(StatusCode, Json<CreateAppCredentialResponseBody>), HTTPError> {

  let http_transaction = http_transaction.clone();

  // Verify the request body.
  ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let app_credential_properties_json = match body {

    Ok(app_credential_properties_json) => app_credential_properties_json,

    Err(error) => {

      let http_error = match error {

        JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

        JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

        JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

        JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  // Make sure the authenticated_user can create access policies for the target action.
  let target_app = get_app_from_id(&app_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_app, &AccessPolicyResourceType::App, &target_app.id, &http_transaction, &state.database_pool).await?;
  let create_app_credentials_action = get_action_from_name("slashstep.appCredentials.create", &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(&authenticated_user, &authenticated_app)?;
  verify_principal_permissions(&authenticated_principal, &create_app_credentials_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &state.database_pool).await?;

  // Create the key pair.
  let mut os_rng = OsRng;
  let signing_key = SigningKey::generate(&mut os_rng);
  let private_key = match signing_key.to_pkcs8_pem(LineEnding::LF) {

    Ok(private_key) => private_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create authenticated_app credential: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let verifying_key = signing_key.verifying_key();
  let public_key = match verifying_key.to_public_key_pem(LineEnding::LF) {

    Ok(public_key) => public_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create authenticated_app credential: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  // Create the authenticated_app credential.
  ServerLogEntry::trace(&format!("Creating authenticated_app credential for authenticated_app {}...", target_app.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let created_app_credential = match AppCredential::create(&InitialAppCredentialProperties {
    app_id: target_app.id,
    description: app_credential_properties_json.description.clone(),
    expiration_date: app_credential_properties_json.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())),
    creation_ip_address: http_transaction.ip_address.clone(),
    public_key: public_key.clone()
  }, &state.database_pool).await {

    Ok(created_app_credential) => created_app_credential,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create authenticated_app credential: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };
  let create_app_credential_response_body = CreateAppCredentialResponseBody {
    id: created_app_credential.id,
    app_id: created_app_credential.app_id,
    description: created_app_credential.description,
    expiration_date: created_app_credential.expiration_date,
    creation_ip_address: created_app_credential.creation_ip_address,
    public_key: public_key.to_string(),
    private_key: private_key.to_string()
  };

  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_app_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::AppCredential,
    target_app_credential_id: Some(created_app_credential.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created authenticated_app credential {}.", created_app_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(create_app_credential_response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps/{app_id}/app-credentials", axum::routing::get(handle_list_app_credentials_request))
    .route("/apps/{app_id}/app-credentials", axum::routing::post(handle_create_app_credential_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}
