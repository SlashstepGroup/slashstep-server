/**
 * 
 * Any test cases for /sessions should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;
use ntest::timeout;
use crate::{
  AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, initialize_predefined_configurations, 
    initialize_predefined_roles
  }, resources::{
    ResourceType, access_policy::{
      AccessPolicy, AccessPolicyPrincipalType, ActionPermissionLevel, InitialAccessPolicyProperties
    }, action::Action, role::Role, session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, Session}
  }, routes::{ListResourcesResponseBody, sessions::LoginCredentials}, tests::{TestEnvironment, TestSlashstepServerError}
};


/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "apps.create" action.
  let create_sessions_action = Action::get_by_name("sessions.create", &test_environment.database_pool).await?;
  let anonymous_users_role = Role::list("protected_role_type = 'AnonymousUsers' LIMIT 1", &test_environment.database_pool, None, None).await?.first().expect("There should be an anonymous users role.").clone();
  AccessPolicy::create(&InitialAccessPolicyProperties {
    principal_type: AccessPolicyPrincipalType::Role,
    principal_role_id: Some(anonymous_users_role.id),
    action_id: create_sessions_action.id,
    permission_level: ActionPermissionLevel::User,
    scoped_resource_type: ResourceType::Server,
    is_inheritance_enabled: true,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create a dummy resource.
  let plain_text_password = Uuid::now_v7().to_string();
  let dummy_user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let login_credentials = LoginCredentials {
    username: dummy_user.username.expect("User should have a username.").clone(),
    password: plain_text_password,
  };
  test_environment.create_server_access_policy(&dummy_user.id, &create_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post("/sessions")
    .json(&serde_json::json!(login_credentials))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_session: Session = response.json();
  assert_eq!(dummy_user.id, response_session.user_id);
  assert_eq!(IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)), response_session.creation_ip_address);
  // TODO: Add assertions for expiration date

  return Ok(());
  
}

/// Verifies that the server returns a 400 status code when the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_json_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post("/sessions")
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "username": true,
      "password": 123
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let create_sessions_action = Action::get_by_name("sessions.create", &test_environment.database_pool).await?;
  let anonymous_users_role = Role::list("protected_role_type = 'AnonymousUsers' LIMIT 1", &test_environment.database_pool, None, None).await?.first().expect("There should be an anonymous users role.").clone();
  AccessPolicy::create(&InitialAccessPolicyProperties {
    principal_type: AccessPolicyPrincipalType::Role,
    principal_role_id: Some(anonymous_users_role.id),
    action_id: create_sessions_action.id,
    permission_level: ActionPermissionLevel::User,
    scoped_resource_type: ResourceType::Server,
    is_inheritance_enabled: true,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let dummy_user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  test_environment.create_server_access_policy(&dummy_user.id, &create_sessions_action.id, &ActionPermissionLevel::None).await?;
  let login_credentials = LoginCredentials {
    username: dummy_user.username.expect("User should have a username.").clone(),
    password: plain_text_password,
  };

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/sessions"))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(login_credentials))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Grant access to the "sessions.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_sessions_action = Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "sessions.list" action to the user.
  let list_sessions_action = Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy delegation policy.
  test_environment.create_random_session(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/sessions"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Session> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_session_count = Session::count("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.total_count, actual_session_count);

  let actual_sessions = Session::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.resources.len(), actual_sessions.len());

  for actual_session in actual_sessions {

    let found_access_policy = response_json.resources.iter().find(|session| session.id == actual_session.id);
    assert!(found_access_policy.is_some());

  }

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "apps.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_sessions_action = Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "apps.list" action to the user.
  let list_sessions_action = Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy delegation policy.
  let dummy_session = test_environment.create_random_session(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let query = format!("id = {}", quote_literal(&dummy_session.id.to_string()));
  let response = test_server.get(&format!("/sessions"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Session> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_session_count = Session::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.total_count, actual_session_count);

  let actual_sessions = Session::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.resources.len(), actual_sessions.len());

  for actual_session in actual_sessions {

    let found_action = response_json.resources.iter().find(|session| session.id == actual_session.id);
    assert!(found_action.is_some());

  }

  return Ok(());

}

/// Verifies that there's a default list limit.
#[tokio::test]
#[timeout(20000)]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "sessions.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_sessions_action = Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "sessions.list" action to the user.
  let list_sessions_action = Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy delegation policies.
  let session_count = Session::count("", &test_environment.database_pool, None, None).await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - session_count + 1) {

    test_environment.create_random_session(Some(&user.id)).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get("/sessions")
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Session> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "sessions.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_sessions_action = Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "apps.list" action to the user.
  let list_sessions_action = Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/sessions"))
    .add_query_param("query", format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_validity() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "sessions.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_sessions_action = Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "sessions.list" action to the user.
  let list_sessions_action = Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_sessions_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let bad_requests = vec![
    test_server.get(&format!("/sessions"))
      .add_query_param("query", format!("id ~ {}", quote_literal(&get_sessions_action.id.to_string()))),
    test_server.get(&format!("/sessions"))
      .add_query_param("query", format!("SELECT * FROM sessions")),
    test_server.get(&format!("/sessions"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/sessions"))
      .add_query_param("query", format!("id = null; SELECT * FROM sessions WHERE id = {}", quote_literal(&get_sessions_action.id.to_string())))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/sessions"))
      .add_query_param("query", format!("1 = 1")),
  ];

  for request in unprocessable_entity_requests {

    let response = request
      .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  }

  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/sessions"))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a user and a session.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/sessions"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}