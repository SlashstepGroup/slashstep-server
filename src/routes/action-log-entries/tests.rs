/**
 * 
 * Any test cases for /action-log-entries should be handled here.
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
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{
  AppState, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, resources::{
    access_policy::{
      AccessPolicy, 
      AccessPolicyPermissionLevel, 
      AccessPolicyPrincipalType, 
      AccessPolicyResourceType, 
      IndividualPrincipal, 
      InitialAccessPolicyProperties
    }, 
    action::Action, action_log_entry::{ActionLogEntry, DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT}, session::Session
  }, routes::action_log_entries::ListActionLogEntryResponseBody, tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested action log entry list.
#[tokio::test]
async fn verify_returned_action_log_entry_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actionLogEntries.get" action to the user.
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

  // Grant access to the "slashstep.actionLogEntries.list" action to the user.
  let list_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create a dummy action log entry.
  test_environment.create_random_action_log_entry().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/action-log-entries"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_json: ListActionLogEntryResponseBody = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.action_log_entries.len() > 0);

  const LIST_OFFSET: i64 = 1;
  let actual_action_count = ActionLogEntry::count("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count + LIST_OFFSET, actual_action_count);

  let actual_action_log_entries = ActionLogEntry::list("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.action_log_entries.len() + LIST_OFFSET as usize, actual_action_log_entries.len());

  let mut remaining_list_offset = LIST_OFFSET;
  for actual_action_log_entry in actual_action_log_entries {

    let found_access_policy = response_json.action_log_entries.iter().find(|action_log_entry| action_log_entry.id == actual_action_log_entry.id);
    
    if !found_access_policy.is_some() {

      if remaining_list_offset > 0 {

        remaining_list_offset -= 1;

      } else {

        panic!("Couldn't find action log entry with ID {}.", actual_action_log_entry.id);

      }

    }

  }

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested action log entry list.
#[tokio::test]
async fn verify_returned_action_log_entry_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actionLogEntries.get" action to the user.
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

  // Grant access to the "slashstep.actionLogEntries.list" action to the user.
  let list_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create a dummy action log entry.
  let dummy_action_log_entry = test_environment.create_random_action_log_entry().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let query = format!("action_id = {}", quote_literal(&dummy_action_log_entry.action_id.to_string()));
  let response = test_server.get(&format!("/action-log-entries"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_json: ListActionLogEntryResponseBody = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.action_log_entries.len() > 0);

  let actual_action_count = ActionLogEntry::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_action_count);

  let actual_action_log_entries = ActionLogEntry::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.action_log_entries.len(), actual_action_log_entries.len());

  for actual_action_log_entry in actual_action_log_entries {

    let found_access_policy = response_json.action_log_entries.iter().find(|action_log_entry| action_log_entry.id == actual_action_log_entry.id);
    
    assert!(found_access_policy.is_some(), "Couldn't find action log entry with ID {}.", actual_action_log_entry.id);

  }

  return Ok(());

}

/// Verifies that there's a default action log entry list limit.
#[tokio::test]
async fn verify_default_action_log_entry_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actionLogEntries.get" action to the user.
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

  // Grant access to the "slashstep.actionLogEntries.list" action to the user.
  let list_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create dummy actions.
  let action_log_entry_count = ActionLogEntry::count("", &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT - action_log_entry_count + 1) {

    test_environment.create_random_action_log_entry().await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/action-log-entries"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListActionLogEntryResponseBody = response.json();
  assert_eq!(response_body.action_log_entries.len(), DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_action_log_entry_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actionLogEntries.get" action to the user.
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

  // Grant access to the "slashstep.actionLogEntries.list" action to the user.
  let list_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/action-log-entries"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_action_log_entries() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actionLogEntries.get" action to the user.
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

  // Grant access to the "slashstep.actionLogEntries.list" action to the user.
  let list_action_log_entries_action = Action::get_by_name("slashstep.actionLogEntries.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_action_log_entries_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let requests = vec![
    test_server.get(&format!("/action-log-entries"))
      .add_query_param("query", format!("action_id = {}", get_action_log_entries_action.id)),
    test_server.get(&format!("/action-log-entries"))
      .add_query_param("query", format!("SELECT * FROM actions")),
    test_server.get(&format!("/action-log-entries"))
      .add_query_param("query", format!("1 = 1")),
    test_server.get(&format!("/action-log-entries"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/action-log-entries"))
      .add_query_param("query", format!("SELECT * FROM actions WHERE id = {}", get_action_log_entries_action.id))
  ];
  
  for request in requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  }

  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_listing_action_log_entries() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/action-log-entries"))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_action_log_entries() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create a user and a session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/action-log-entries"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}