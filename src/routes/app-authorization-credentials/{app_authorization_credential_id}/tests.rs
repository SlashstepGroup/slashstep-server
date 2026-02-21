/**
 * 
 * Any test cases for /app-authorization-credentials/{action_id} should be handled here.
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
use ntest::timeout;
use reqwest::StatusCode;
use crate::{
  Action, AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, resources::{
    ResourceError, access_policy::ActionPermissionLevel, app_authorization_credential::AppAuthorizationCredential,
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(20000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_authorizations_action = Action::get_by_name("slashstep.appAuthorizationCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_authorizations_action.id, &ActionPermissionLevel::User).await?;
  
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;

  let response = test_server.get(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_app_authorization_credential: AppAuthorizationCredential = response.json();
  assert_eq!(response_app_authorization_credential.id, app_authorization_credential.id);
  assert_eq!(response_app_authorization_credential.app_authorization_id, app_authorization_credential.app_authorization_id);
  assert_eq!(response_app_authorization_credential.access_token_expiration_date, app_authorization_credential.access_token_expiration_date);
  assert_eq!(response_app_authorization_credential.refresh_token_expiration_date, app_authorization_credential.refresh_token_expiration_date);
  assert_eq!(response_app_authorization_credential.refreshed_app_authorization_credential_id, app_authorization_credential.refreshed_app_authorization_credential_id);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the resource ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get("/app-authorization-credentials/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;

  let response = test_server.get(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .await;
  
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the resource.
#[tokio::test]
#[timeout(20000)]
async fn verify_permission_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create the user, the session, and the resource.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested resource doesn't exist.
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-authorization-credentials/{}", uuid::Uuid::now_v7()))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 204 status code if the resource is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Grant access to the "slashstep.appAuthorizationCredentials.delete" action to the user.
  let delete_app_authorizations_action = Action::get_by_name("slashstep.appAuthorizationCredentials.delete", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &delete_app_authorizations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 204);

  match AppAuthorizationCredential::get_by_id(&app_authorization_credential.id, &test_environment.database_pool).await.expect_err("Expected a not found error.") {

    ResourceError::NotFoundError(_) => {},

    error => return Err(TestSlashstepServerError::ResourceError(error))

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the resource ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.delete("/app-authorization-credentials/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create dummy resources.
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the resource.
#[tokio::test]
async fn verify_permission_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create dummy resources.
  let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/app-authorization-credentials/{}", app_authorization_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the resource does not exist.
#[tokio::test]
async fn verify_resource_exists_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/app-authorization-credentials/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}