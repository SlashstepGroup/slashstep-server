/**
 * 
 * Any test cases for /users/{user_id}/oauth-authorizations should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::net::SocketAddr;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::ActionPermissionLevel, action::Action, oauth_authorization::{InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer},}, routes::users::user_id::oauth_authorizations::CreateOAuthAuthorizationResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "slashstep.apps.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_oauth_authorizations_action = Action::get_by_name("slashstep.oauthAuthorizations.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_oauth_authorizations_action.id, &ActionPermissionLevel::User).await?;
  let authorize_app_action = Action::get_by_name("slashstep.apps.authorize", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &authorize_app_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;
  let dummy_user = test_environment.create_random_user().await?;
  let dummy_action = test_environment.create_random_action(None).await?;

  // Set up the server and send the request.
  let initial_oauth_authorization_properties = InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer {
    app_id: dummy_app.id,
    code_challenge: None,
    scope: format!("{}:Editor", dummy_action.id),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/users/{}/oauth-authorizations", dummy_user.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_oauth_authorization_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  let response_oauth_authorization: CreateOAuthAuthorizationResponseBody = response.json();
  assert_eq!(initial_oauth_authorization_properties.app_id, response_oauth_authorization.oauth_authorization.app_id);
  assert_eq!(dummy_user.id, response_oauth_authorization.oauth_authorization.authorizing_user_id);
  assert_eq!(initial_oauth_authorization_properties.code_challenge, response_oauth_authorization.oauth_authorization.code_challenge);
  // assert_eq!(initial_oauth_authorization_properties.app_id, response_oauth_authorization.app_id);
  // assert_eq!(dummy_user.id, response_oauth_authorization.authorizing_user_id);
  // assert_eq!(initial_oauth_authorization_properties.code_challenge, response_oauth_authorization.code_challenge);

  return Ok(());
  
}