/**
 * 
 * Any functionality for /oauth-access-tokens should be handled here.
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
use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash};
use axum::{Extension, Json, Router, extract::{Query, State}};
use base64::{Engine, engine::general_purpose};
use chrono::{Duration, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware::get_decoding_key, http_request_middleware}, resources::{DeletableResource, ResourceError, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, AppClientType}, app_authorization::{AppAuthorization, AppAuthorizationAuthorizingResourceType, InitialAppAuthorizationProperties}, app_authorization_credential::{AppAuthorizationCredential, InitialAppAuthorizationCredentialProperties}, http_transaction::HTTPTransaction, oauth_authorization::{EditableOAuthAuthorizationProperties, OAuthAuthorization, OAuthAuthorizationClaims}, server_log_entry::ServerLogEntry}, utilities::route_handler_utilities::{get_action_by_name, get_json_web_token_private_key, get_json_web_token_public_key}};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CreateOAuthAccessTokenQueryParameters {
  pub client_id: String,
  pub client_secret: Option<String>,
  pub code: String,
  pub redirect_uri: String,
  pub code_verifier: Option<String>,
  pub grant_type: String
}

#[derive(Debug, Serialize)]
pub struct OAuthError {
  pub error: String,
  pub error_description: String,
  pub error_uri: Option<String>,
  pub state: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccessTokenResponseBody {
  pub access_token: String,
  pub token_type: String,
  pub expires_in: i64,
  pub refresh_expires_in: i64,
  pub refresh_token: Option<String>,
  pub state: Option<String>,
  pub app_authorization_credential_id: Uuid
}

impl OAuthError {

  pub fn new(error: &str, error_description: &str, error_uri: Option<&str>, state: Option<&String>) -> Self {

    OAuthError {
      error: error.to_string(),
      error_description: error_description.to_string(),
      error_uri: error_uri.map(|error_uri| error_uri.to_string()),
      state: state.cloned()
    }

  }

}

pub async fn convert_client_id_string_to_uuid(client_id: &str, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Uuid, HTTPError> {

  ServerLogEntry::trace(format!("Converting client ID \"{}\" to UUID...", client_id).as_str(), Some(&http_transaction_id), &database_pool).await.ok();

  let client_id = match Uuid::parse_str(client_id) {

    Ok(client_id) => client_id,

    Err(_) => {

      let oauth_error = OAuthError::new("invalid_client", "The client ID must be a valid UUID.", None, None);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(client_id);

}

pub async fn decode_json_web_token_claims(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, json_web_token_public_key: &str, token: &str) -> Result<jsonwebtoken::TokenData<OAuthAuthorizationClaims>, HTTPError> {

  ServerLogEntry::trace("Decoding and verifying authorization code...", Some(&http_transaction_id), &database_pool).await.ok();

  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
  let decoding_key = get_decoding_key(&http_transaction_id, &database_pool, &json_web_token_public_key).await?;
  let decoded_claims = match jsonwebtoken::decode::<OAuthAuthorizationClaims>(token, &decoding_key, &validation) {

    Ok(decoded_claims) => decoded_claims,

    Err(error) => {

      let http_error = match &error.kind() {

        jsonwebtoken::errors::ErrorKind::InvalidToken => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),

        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claims) => {
         
          ServerLogEntry::warning(&format!("Missing required claim \"{}\" in session token.", claims), Some(&http_transaction_id), &database_pool).await.ok();
          HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()))
          
        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(decoded_claims);

}

pub async fn get_app_by_client_id(client_id: &Uuid, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<App, HTTPError> {

  ServerLogEntry::trace(format!("Getting app for client ID \"{}\"...", client_id).as_str(), Some(&http_transaction_id), &database_pool).await.ok();

  let app = match App::get_by_id(client_id, database_pool).await {

    Ok(app) => app,

    Err(error) => {

      let http_error = match error {

        ResourceError::NotFoundError(_) => HTTPError::NotFoundError(Some(format!("The app with the client ID \"{}\" does not exist.", client_id))),

        _ => HTTPError::InternalServerError(Some(format!("Failed to get app with the client ID \"{}\": {:?}", client_id, error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app);

}

pub async fn get_oauth_authorization_by_id(oauth_authorization_id: &Uuid, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<OAuthAuthorization, HTTPError> {

  ServerLogEntry::trace(format!("Getting OAuth authorization {}...", oauth_authorization_id).as_str(), Some(&http_transaction_id), &database_pool).await.ok();

  let oauth_authorization = match OAuthAuthorization::get_by_id(oauth_authorization_id, database_pool).await {

    Ok(oauth_authorization) => oauth_authorization,

    Err(error) => {

      let http_error = match error {

        ResourceError::NotFoundError(_) => HTTPError::NotFoundError(Some(format!("The OAuth authorization with the ID \"{}\" does not exist.", oauth_authorization_id))),

        _ => HTTPError::InternalServerError(Some(format!("Failed to get OAuth authorization with the ID \"{}\": {:?}", oauth_authorization_id, error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(oauth_authorization);

}

pub async fn convert_oauth_authorization_id_string_to_uuid(oauth_authorization_id: &str, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Uuid, HTTPError> {

  ServerLogEntry::trace(format!("Converting OAuth authorization ID \"{}\" to UUID...", oauth_authorization_id).as_str(), Some(&http_transaction_id), &database_pool).await.ok();

  let oauth_authorization_id = match Uuid::parse_str(oauth_authorization_id) {

    Ok(oauth_authorization_id) => oauth_authorization_id,

    Err(_) => {

      let oauth_error = OAuthError::new("invalid_grant", "The authorization code is invalid.", None, None);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(oauth_error) => HTTPError::UnauthorizedError(Some(oauth_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(oauth_authorization_id);

}

pub async fn verify_client_secret(client_secret: Option<&str>, client_secret_hash: Option<&str>, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  ServerLogEntry::trace("Verifying client secret is present...", Some(&http_transaction_id), &database_pool).await.ok();

  let client_secret = match client_secret {

    Some(client_secret) => client_secret,

    None => {

      let oauth_error = OAuthError::new("invalid_client", "The client ID or client secret is incorrect.", None, None);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(http_error) => HTTPError::UnauthorizedError(Some(http_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace("Converting client secret hash string to Argon2 password hash...", Some(&http_transaction_id), &database_pool).await.ok();
  let client_secret_hash_string = match client_secret_hash {

    Some(client_secret_hash_string) => client_secret_hash_string,

    None => {

      let http_error = HTTPError::InternalServerError(Some("The app is confidential, but the client secret hash is not set. Database table constraints should have prevented this from happening.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }
    
  };

  let client_secret_hash = match PasswordHash::new(&client_secret_hash_string) {

    Ok(client_secret_hash) => client_secret_hash,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to parse client secret hash: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace("Verifying client secret is correct...", Some(&http_transaction_id), &database_pool).await.ok();
  match Argon2::default().verify_password(client_secret.as_bytes(), &client_secret_hash) {

    Ok(_) => {},

    Err(error) => {

      let http_error = match error {

        password_hash::Error::Password => HTTPError::UnauthorizedError(Some("The client ID or client secret is incorrect.".to_string())),

        _ => HTTPError::InternalServerError(Some(format!("Failed to verify client secret: {:?}", error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  }

  return Ok(());

}

pub async fn update_oauth_authorization_usage_date(oauth_authorization: &OAuthAuthorization, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  ServerLogEntry::trace(&format!("Updating OAuth authorization {} with a usage date...", oauth_authorization.id), Some(&http_transaction_id), &database_pool).await.ok();
  
  match oauth_authorization.update(&EditableOAuthAuthorizationProperties {
    usage_date: Some(Utc::now())
  }, &database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to update OAuth authorization: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  }

  return Ok(());

}

pub async fn create_app_authorization(oauth_authorization: &OAuthAuthorization, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorization, HTTPError> {

  ServerLogEntry::trace("Creating app authorization...", Some(&http_transaction.id), &database_pool).await.ok();

  let app_authorization = match AppAuthorization::create(&InitialAppAuthorizationProperties {
    app_id: oauth_authorization.app_id,
    authorizing_resource_type: AppAuthorizationAuthorizingResourceType::User,
    authorizing_user_id: Some(oauth_authorization.authorizing_user_id),
    oauth_authorization_id: Some(oauth_authorization.id),
    ..Default::default()
  }, &database_pool).await {

    Ok(app_authorization) => app_authorization,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create app authorization: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  let create_app_authorizations_action = get_action_by_name("slashstep.appAuthorizations.create", &http_transaction, &database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_app_authorizations_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::App,
    actor_user_id: None,
    actor_app_id: Some(oauth_authorization.app_id),
    target_resource_type: ActionLogEntryTargetResourceType::AppAuthorization,
    target_app_authorization_id: Some(app_authorization.id),
    reason: Some("OAuth authorization code was used to create an app authorization.".to_string()),
    ..Default::default()
  }, &database_pool).await.ok();

  return Ok(app_authorization);

}

pub async fn verify_code_verifier(code_verifier: Option<&str>, code_challenge: &str, code_challenge_method: Option<&str>, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, oauth_state: Option<&String>) -> Result<(), HTTPError> {

  ServerLogEntry::trace("Verifying code_verifier...", Some(&http_transaction_id), &database_pool).await.ok();

  if code_challenge_method.is_none_or(|code_challenge_method| code_challenge_method != "S256") {
    
    let oauth_error = OAuthError::new("invalid_request", "The code challenge method must be \"S256\".", None, oauth_state);
    let http_error = match serde_json::to_string_pretty(&oauth_error) {
      
      Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
      
      Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
      
    };
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
    return Err(http_error);
    
  }

  let code_verifier = match code_verifier {
    
    Some(code_verifier) => code_verifier,
    
    None => {
      
      let oauth_error = OAuthError::new("invalid_request", "The code verifier is required.", None, oauth_state);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {
        
        Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
        
        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
        
      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);
      
    }

  };

  let hashed_code_verifier = Sha256::digest(code_verifier.as_bytes());
  let base64_hashed_code_verifier = general_purpose::STANDARD.encode(hashed_code_verifier);
  if code_challenge != &base64_hashed_code_verifier {
    
    let oauth_error = OAuthError::new("invalid_grant", "The code verifier is incorrect.", None, oauth_state);
    let http_error = match serde_json::to_string_pretty(&oauth_error) {
      
      Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
      
      Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
      
    };
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
    return Err(http_error);
    
  }

  return Ok(());

}

pub async fn delete_oauth_authorization(oauth_authorization: &OAuthAuthorization, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  ServerLogEntry::trace(&format!("Deleting OAuth authorization {}...", oauth_authorization.id), Some(&oauth_authorization.id), database_pool).await.ok();

  match oauth_authorization.delete(database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete OAuth authorization: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&oauth_authorization.id), database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(());

}

pub async fn create_app_authorization_credential(app_authorization_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorizationCredential, HTTPError> {

  ServerLogEntry::trace(&format!("Creating app authorization credential for app authorization {}...", app_authorization_id), Some(&http_transaction.id), database_pool).await.ok();

  let app_authorization_credential = match AppAuthorizationCredential::create(&InitialAppAuthorizationCredentialProperties {
    app_authorization_id: *app_authorization_id,
    access_token_expiration_date: Utc::now() + Duration::hours(8),
    refresh_token_expiration_date: Utc::now() + Duration::days(30),
    refreshed_app_authorization_credential_id: None
  }, &database_pool).await {

    Ok(app_authorization_credential) => app_authorization_credential,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create app authorization credential: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_authorization_credential);

}

pub async fn get_app_authorization_by_oauth_authorization_id(oauth_authorization_id: &Uuid, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<AppAuthorization, HTTPError> {

  ServerLogEntry::trace(&format!("Getting app authorization for OAuth authorization {}...", oauth_authorization_id), Some(&http_transaction.id), database_pool).await.ok();

  let app_authorization = match AppAuthorization::get_by_oauth_authorization_id(oauth_authorization_id, database_pool).await {

    Ok(app_authorization) => app_authorization,

    Err(error) => {

      let http_error = match error {

        ResourceError::NotFoundError(_) => HTTPError::NotFoundError(Some(format!("The app authorization for the OAuth authorization with the ID \"{}\" does not exist.", oauth_authorization_id))),

        _ => HTTPError::InternalServerError(Some(format!("Failed to get app authorization for OAuth authorization: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(app_authorization);

}

pub async fn delete_app_authorization(app_authorization: &AppAuthorization, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

  match app_authorization.delete(&database_pool).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app authorization: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

  }

  let delete_app_authorizations_action = get_action_by_name("slashstep.appAuthorizations.delete", &http_transaction, &database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: delete_app_authorizations_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::Server,
    target_resource_type: ActionLogEntryTargetResourceType::AppAuthorization,
    target_app_authorization_id: Some(app_authorization.id),
    reason: Some("OAuth authorization code was reused. Deleting this app authorization in accordance with the OAuth 2.0 specification.".to_string()),
    ..Default::default()
  }, &database_pool).await.ok();

  return Ok(());

}

/// POST /users/{user_id}/oauth-authorizations
/// 
/// Creates an OAuth authorization for a user.
#[axum::debug_handler]
async fn handle_create_oauth_access_token_request(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Query(query_parameters): Query<CreateOAuthAccessTokenQueryParameters>,
) -> Result<(StatusCode, Json<CreateAccessTokenResponseBody>), HTTPError> {
  
  let http_transaction = http_transaction.clone();
  let client_id = convert_client_id_string_to_uuid(&query_parameters.client_id, &http_transaction.id, &state.database_pool).await?;
  let app = get_app_by_client_id(&client_id, &http_transaction.id, &state.database_pool).await?;

  if app.client_type == AppClientType::Confidential {

    verify_client_secret(query_parameters.client_secret.as_deref(), app.client_secret_hash.as_deref(), &http_transaction.id, &state.database_pool).await?;

  }

  let app_authorization: AppAuthorization;
  let oauth_state: Option<String>;
  if query_parameters.grant_type == "authorization_code" {

    let json_web_token_public_key = get_json_web_token_public_key(&http_transaction.id, &state.database_pool).await?;
    let decoded_claims = decode_json_web_token_claims(&http_transaction.id, &state.database_pool, &json_web_token_public_key, &query_parameters.code).await?;
    let oauth_authorization_id = convert_oauth_authorization_id_string_to_uuid(&decoded_claims.claims.jti, &http_transaction.id, &state.database_pool).await?;
    let oauth_authorization = get_oauth_authorization_by_id(&oauth_authorization_id, &http_transaction.id, &state.database_pool).await?;
    oauth_state = oauth_authorization.state.clone();

    // More information: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    if oauth_authorization.redirect_uri.is_some() && oauth_authorization.redirect_uri != Some(query_parameters.redirect_uri) {

      let oauth_error = OAuthError::new("invalid_grant", "The redirect URI is invalid.", None, oauth_state.as_ref());
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

    // Authorization codes are single-use (https://datatracker.ietf.org/doc/html/rfc6749#section-10.5), 
    // so we should add a usage date to the OAuth authorization to prevent it from being used multiple times.
    if oauth_authorization.usage_date.is_some() {

      delete_oauth_authorization(&oauth_authorization, &state.database_pool).await?;
      let app_authorization = get_app_authorization_by_oauth_authorization_id(&oauth_authorization_id, &http_transaction, &state.database_pool).await?;
      delete_app_authorization(&app_authorization, &http_transaction, &state.database_pool).await?;
      let oauth_error = OAuthError::new("invalid_grant", "The authorization code is invalid.", None, oauth_state.as_ref());
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(oauth_error) => HTTPError::BadRequestError(Some(oauth_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

    update_oauth_authorization_usage_date(&oauth_authorization, &http_transaction.id, &state.database_pool).await?;

    if let Some(code_challenge) = &oauth_authorization.code_challenge {

      verify_code_verifier(query_parameters.code_verifier.as_deref(), &code_challenge, oauth_authorization.code_challenge_method.as_deref(), &http_transaction.id, &state.database_pool, oauth_state.as_ref()).await?;
      
    }

    app_authorization = create_app_authorization(&oauth_authorization, &http_transaction, &state.database_pool).await?;

  } else if query_parameters.grant_type == "refresh_token" {

    // TODO: Implement refresh token grant type.
    return Err(HTTPError::NotImplementedError(Some("Refresh token grant type is not implemented.".to_string())));

  } else {

    let oauth_error = OAuthError::new("unsupported_grant_type", "The grant type is not supported.", None, None);
    let http_error = match serde_json::to_string_pretty(&oauth_error) {

      Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),

      Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

    };
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let app_authorization_credential = create_app_authorization_credential(&app_authorization.id, &http_transaction, &state.database_pool).await?;
  let json_web_token_private_key = get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?;
  let access_token = match app_authorization_credential.generate_access_token(&json_web_token_private_key) {

    Ok(access_token) => access_token,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to generate access token: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };
  let refresh_token = match app_authorization_credential.generate_refresh_token(&json_web_token_private_key) {

    Ok(refresh_token) => Some(refresh_token),

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to generate refresh token: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let access_token_response_body = CreateAccessTokenResponseBody {
    access_token,
    token_type: "Bearer".to_string(),
    expires_in: Utc::now().signed_duration_since(app_authorization_credential.access_token_expiration_date).num_seconds(),
    refresh_expires_in: Utc::now().signed_duration_since(app_authorization_credential.refresh_token_expiration_date).num_seconds(),
    refresh_token,
    state: oauth_state,
    app_authorization_credential_id: app_authorization_credential.id
  };

  let create_app_authorization_credentials_action = get_action_by_name("slashstep.appAuthorizationCredentials.create", &http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_app_authorization_credentials_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::App,
    actor_app_id: Some(app_authorization.app_id),
    target_resource_type: ActionLogEntryTargetResourceType::AppAuthorizationCredential,
    target_app_authorization_credential_id: Some(app_authorization_credential.id),
    reason: Some("OAuth was used to create an app authorization credential.".to_string()),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully created app authorization credential {}.", app_authorization_credential.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(access_token_response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/oauth-access-tokens", axum::routing::post(handle_create_oauth_access_token_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}