/**
 * 
 * Any test cases for /oauth-access-tokens should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::net::SocketAddr;
use argon2::{Argon2, PasswordHasher, password_hash::{SaltString, rand_core::OsRng}};
use axum_test::TestServer;
use base64::{Engine, engine::general_purpose};
use chrono::{Duration, Utc};
use jsonwebtoken::Header;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{app::{App, AppClientType, EditableAppProperties}, app_authorization_credential::AppAuthorizationCredentialClaims}, routes::oauth_access_tokens::{CreateAccessTokenResponseBody, CreateOAuthAccessTokenQueryParameters, OAuthTokenError, OAuthTokenErrorResponse}, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_public_client_with_authorization_code() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_public_client_with_authorization_code_and_code_challenge() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let code_verifier = Uuid::now_v7().to_string();
  let hashed_code_challenge = Sha256::digest(code_verifier.as_bytes());
  let base64_hashed_code_challenge = general_purpose::STANDARD.encode(hashed_code_challenge);
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, Some(&base64_hashed_code_challenge)).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    code_verifier: Some(code_verifier.to_string()),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_confidential_client_with_authorization_code() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let app = App::get_by_id(&dummy_oauth_authorization.app_id, &test_environment.database_pool).await.expect("Expected a dummy app to exist.");
  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);
  let new_client_secret = Uuid::now_v7().to_string();
  let hashed_client_secret = argon2.hash_password(new_client_secret.as_bytes(), &salt).expect("Failed to hash client secret.");
  app.update(&EditableAppProperties {
    client_type: Some(AppClientType::Confidential),
    client_secret_hash: Some(hashed_client_secret.to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    client_secret: Some(new_client_secret),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_confidential_client_with_authorization_code_and_code_challenge() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let code_verifier = Uuid::now_v7().to_string();
  let hashed_code_challenge = Sha256::digest(code_verifier.as_bytes());
  let base64_hashed_code_challenge = general_purpose::STANDARD.encode(hashed_code_challenge);
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, Some(&base64_hashed_code_challenge)).await?;
  let app = App::get_by_id(&dummy_oauth_authorization.app_id, &test_environment.database_pool).await.expect("Expected a dummy app to exist.");
  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);
  let new_client_secret = Uuid::now_v7().to_string();
  let hashed_client_secret = argon2.hash_password(new_client_secret.as_bytes(), &salt).expect("Failed to hash client secret.");
  app.update(&EditableAppProperties {
    client_type: Some(AppClientType::Confidential),
    client_secret_hash: Some(hashed_client_secret.to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    client_secret: Some(new_client_secret),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    code_verifier: Some(code_verifier),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the client ID is not a UUID.
#[tokio::test]
async fn verify_client_id_is_uuid() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: "not-a-uuid".to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidClient);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the authorization code is invalid.
#[tokio::test]
async fn verify_authorization_code_is_valid() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some("not-a-valid-code".to_string()),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidGrant);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the authoirzation code has already been used.
#[tokio::test]
async fn verify_authorization_code_is_single_use() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let send_request = async || {

    let state = AppState {
      database_pool: test_environment.database_pool.clone(),
    };
    let router = super::get_router(state.clone())
      .with_state(state)
      .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router)?;
    let response = test_server.post("/oauth-access-tokens")
      .add_query_params(create_oauth_access_token_query_parameters)
      .await;

    Ok::<_, TestSlashstepServerError>(response)

  };
  let response = send_request.clone()().await?;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  // Send the request again and verify that it fails.
  let response = send_request.clone()().await?;
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the client ID links to a non-existent app.
#[tokio::test]
async fn verify_client_id_links_to_app() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: Uuid::now_v7().to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidClient);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the client secret is not provided for confidential clients.
#[tokio::test]
async fn verify_client_secret_is_provided_for_confidential_client() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, None).await?;
  let app = App::get_by_id(&dummy_oauth_authorization.app_id, &test_environment.database_pool).await.expect("Expected a dummy app to exist.");
  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);
  let new_client_secret = Uuid::now_v7().to_string();
  let hashed_client_secret = argon2.hash_password(new_client_secret.as_bytes(), &salt).expect("Failed to hash client secret.");
  app.update(&EditableAppProperties {
    client_type: Some(AppClientType::Confidential),
    client_secret_hash: Some(hashed_client_secret.to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidClient);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the code verifier is not provided when a code challenge is present.
#[tokio::test]
async fn verify_code_verifier_is_provided_when_code_challenge_is_present() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let code_verifier = Uuid::now_v7().to_string();
  let hashed_code_challenge = Sha256::digest(code_verifier.as_bytes());
  let base64_hashed_code_challenge = general_purpose::STANDARD.encode(hashed_code_challenge);
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, Some(&base64_hashed_code_challenge)).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidRequest);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the code verifier is incorrect when a code challenge is present.
#[tokio::test]
async fn verify_code_verifier_is_correct_when_code_challenge_is_present() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let code_verifier = Uuid::now_v7().to_string();
  let hashed_code_challenge = Sha256::digest(code_verifier.as_bytes());
  let base64_hashed_code_challenge = general_purpose::STANDARD.encode(hashed_code_challenge);
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None, Some(&base64_hashed_code_challenge)).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: Some(authorization_code),
    grant_type: "authorization_code".to_string(),
    code_verifier: Some("not-the-code-verifier".to_string()),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidGrant);

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_public_client_with_refresh_token() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let dummy_app_authorization_credential = test_environment.create_random_app_authorization_credential(Some(&dummy_app_authorization.id)).await?;
  let refresh_token = dummy_app_authorization_credential.generate_refresh_token(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_app_authorization.app_id.to_string(),
    grant_type: "refresh_token".to_string(),
    refresh_token: Some(refresh_token),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_successful_creation_for_confidential_client_with_refresh_token() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let dummy_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let app = App::get_by_id(&dummy_app_authorization.app_id, &test_environment.database_pool).await.expect("Expected a dummy app to exist.");
  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);
  let new_client_secret = Uuid::now_v7().to_string();
  let hashed_client_secret = argon2.hash_password(new_client_secret.as_bytes(), &salt).expect("Failed to hash client secret.");
  app.update(&EditableAppProperties {
    client_type: Some(AppClientType::Confidential),
    client_secret_hash: Some(hashed_client_secret.to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_app_authorization_credential = test_environment.create_random_app_authorization_credential(Some(&dummy_app_authorization.id)).await?;
  let refresh_token = dummy_app_authorization_credential.generate_refresh_token(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_app_authorization.app_id.to_string(),
    client_secret: Some(new_client_secret),
    grant_type: "refresh_token".to_string(),
    refresh_token: Some(refresh_token),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let _: CreateAccessTokenResponseBody = response.json();

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_active_refresh_token_for_public_client() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let dummy_app_authorization_credential = test_environment.create_random_app_authorization_credential(Some(&dummy_app_authorization.id)).await?;
  let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
  let claims = AppAuthorizationCredentialClaims {
    jti: dummy_app_authorization_credential.id.to_string(),
    // jsonwebtoken automatically adds a leeway of 60 seconds to account for clock skew.
    // https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html#structfield.leeway
    exp: (Utc::now() - Duration::seconds(61)).timestamp() as usize, 
    r#type: "Refresh".to_string()
  };
  let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(json_web_token_private_key.as_ref())?;
  let refresh_token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_app_authorization.app_id.to_string(),
    grant_type: "refresh_token".to_string(),
    refresh_token: Some(refresh_token),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidGrant);

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::CREATED status code and the created resource.
#[tokio::test]
async fn verify_active_refresh_token_for_confidential_client() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let app = App::get_by_id(&dummy_app_authorization.app_id, &test_environment.database_pool).await.expect("Expected a dummy app to exist.");
  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);
  let new_client_secret = Uuid::now_v7().to_string();
  let hashed_client_secret = argon2.hash_password(new_client_secret.as_bytes(), &salt).expect("Failed to hash client secret.");
  app.update(&EditableAppProperties {
    client_type: Some(AppClientType::Confidential),
    client_secret_hash: Some(hashed_client_secret.to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let dummy_app_authorization_credential = test_environment.create_random_app_authorization_credential(Some(&dummy_app_authorization.id)).await?;
  let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
  let claims = AppAuthorizationCredentialClaims {
    jti: dummy_app_authorization_credential.id.to_string(),
    // jsonwebtoken automatically adds a leeway of 60 seconds to account for clock skew.
    // https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html#structfield.leeway
    exp: (Utc::now() - Duration::seconds(61)).timestamp() as usize, 
    r#type: "Refresh".to_string()
  };
  let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(json_web_token_private_key.as_ref())?;
  let refresh_token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_app_authorization.app_id.to_string(),
    client_secret: Some(new_client_secret),
    grant_type: "refresh_token".to_string(),
    refresh_token: Some(refresh_token),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidGrant);

  return Ok(());
  
}

/// Verifies that the router can return a StatusCode::BAD_REQUEST status code if the refresh token has invalid claims.
#[tokio::test]
async fn verify_valid_refresh_token_for_public_client() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let dummy_app_authorization_credential = test_environment.create_random_app_authorization_credential(Some(&dummy_app_authorization.id)).await?;
  let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
  let claims = AppAuthorizationCredentialClaims {
    jti: dummy_app_authorization_credential.id.to_string(),
    exp: (Utc::now() + Duration::hours(8)).timestamp() as usize, 
    r#type: "Not Refresh".to_string()
  };
  let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(json_web_token_private_key.as_ref())?;
  let refresh_token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_app_authorization.app_id.to_string(),
    grant_type: "refresh_token".to_string(),
    refresh_token: Some(refresh_token),
    ..Default::default()
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(create_oauth_access_token_query_parameters)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  let oauth_error: OAuthTokenErrorResponse = response.json();
  assert_eq!(oauth_error.error, OAuthTokenError::InvalidGrant);

  return Ok(());
  
}