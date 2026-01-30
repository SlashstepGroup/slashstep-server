/**
 * 
 * Any test cases for /action-log-entries/{action_log_entry_id} should be handled here.
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
use crate::{
  Action, 
  AppState,
  initialize_required_tables,
  predefinitions::{
    initialize_predefined_actions, initialize_predefined_roles
  }, 
  resources::{
    ResourceError, access_policy::{
      AccessPolicy, 
      AccessPolicyPermissionLevel, 
      AccessPolicyPrincipalType, 
      AccessPolicyResourceType, 
      InitialAccessPolicyProperties
    }, action_log_entry::ActionLogEntry, session::Session
  }, 
  tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested action.
#[tokio::test]
#[timeout(20000)]
async fn verify_returned_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;
  
  let action_log_entry = test_environment.create_random_action_log_entry().await?;

  let response = test_server.get(&format!("/action-log-entries/{}", action_log_entry.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);
  let response_action_log_entry: ActionLogEntry = response.json();
  assert_eq!(response_action_log_entry.id, action_log_entry.id);
  assert_eq!(response_action_log_entry.action_id, action_log_entry.action_id);
  assert_eq!(response_action_log_entry.http_transaction_id, action_log_entry.http_transaction_id);
  assert_eq!(response_action_log_entry.actor_type, action_log_entry.actor_type);
  assert_eq!(response_action_log_entry.actor_user_id, action_log_entry.actor_user_id);
  assert_eq!(response_action_log_entry.actor_app_id, action_log_entry.actor_app_id);
  assert_eq!(response_action_log_entry.target_resource_type, action_log_entry.target_resource_type);
  assert_eq!(response_action_log_entry.target_action_id, action_log_entry.target_action_id);
  assert_eq!(response_action_log_entry.target_action_log_entry_id, action_log_entry.target_action_log_entry_id);
  assert_eq!(response_action_log_entry.target_app_id, action_log_entry.target_app_id);
  assert_eq!(response_action_log_entry.target_app_authorization_id, action_log_entry.target_app_authorization_id);
  assert_eq!(response_action_log_entry.target_app_authorization_credential_id, action_log_entry.target_app_authorization_credential_id);
  assert_eq!(response_action_log_entry.target_app_credential_id, action_log_entry.target_app_credential_id);
  assert_eq!(response_action_log_entry.target_group_id, action_log_entry.target_group_id);
  assert_eq!(response_action_log_entry.target_group_membership_id, action_log_entry.target_group_membership_id);
  assert_eq!(response_action_log_entry.target_http_transaction_id, action_log_entry.target_http_transaction_id);
  assert_eq!(response_action_log_entry.target_item_id, action_log_entry.target_item_id);
  assert_eq!(response_action_log_entry.target_milestone_id, action_log_entry.target_milestone_id);
  assert_eq!(response_action_log_entry.target_project_id, action_log_entry.target_project_id);
  assert_eq!(response_action_log_entry.target_role_id, action_log_entry.target_role_id);
  assert_eq!(response_action_log_entry.target_role_membership_id, action_log_entry.target_role_membership_id);
  assert_eq!(response_action_log_entry.target_server_log_entry_id, action_log_entry.target_server_log_entry_id);
  assert_eq!(response_action_log_entry.target_session_id, action_log_entry.target_session_id);
  assert_eq!(response_action_log_entry.target_user_id, action_log_entry.target_user_id);
  assert_eq!(response_action_log_entry.target_workspace_id, action_log_entry.target_workspace_id);
  assert_eq!(response_action_log_entry.reason, action_log_entry.reason);

  return Ok(());

}

/// Verifies that the router can return a 400 if the action log entry ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get("/action-log-entries/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

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
  
  let action_log_entry = test_environment.create_random_action_log_entry().await?;

  let response = test_server.get(&format!("/action-log-entries/{}", action_log_entry.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the action log entry.
#[tokio::test]
#[timeout(20000)]
async fn verify_permission_when_getting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create the user, the session, and the action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let action_log_entry = test_environment.create_random_action_log_entry().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/action-log-entries/{}", action_log_entry.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested action log entry doesn't exist.
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_getting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/action-log-entries/{}", uuid::Uuid::now_v7()))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 204 status code if the action log entry is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Grant access to the "slashstep.actions.delete" action to the user.
  let delete_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.delete", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: delete_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let action_log_entry = test_environment.create_random_action_log_entry().await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/action-log-entries/{}", action_log_entry.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 204);

  match ActionLogEntry::get_by_id(&action_log_entry.id, &test_environment.database_pool).await.expect_err("Expected an action log entry not found error.") {

    ResourceError::NotFoundError(_) => {},

    error => return Err(TestSlashstepServerError::ResourceError(error))

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the action log entry ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

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

  let response = test_server.delete("/action-log-entries/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create a dummy action log entry.
  let action_log_entry = test_environment.create_random_action_log_entry().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/action-log-entries/{}", action_log_entry.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the action log entry.
#[tokio::test]
async fn verify_permission_when_deleting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create a dummy action log entry.
  let action_log_entry = test_environment.create_random_action_log_entry().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/action-log-entries/{}", action_log_entry.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the action log entry does not exist.
#[tokio::test]
async fn verify_action_log_entry_exists_when_deleting_action_log_entry_by_id() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.delete(&format!("/action-log-entries/{}", uuid::Uuid::now_v7()))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}
