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
use axum_test::TestServer;
use reqwest::StatusCode;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::ActionPermissionLevel, action::Action}, routes::oauth_access_tokens::{CreateAccessTokenResponseBody, CreateOAuthAccessTokenQueryParameters, OAuthTokenError, OAuthTokenErrorResponse}, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: authorization_code,
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
  assert_eq!(response.status_code(), 201);

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
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: "not-a-uuid".to_string(),
    code: authorization_code,
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
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None).await?;
  let create_oauth_access_token_query_parameters = CreateOAuthAccessTokenQueryParameters {
    client_id: dummy_oauth_authorization.app_id.to_string(),
    code: "not-a-valid-code".to_string(),
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