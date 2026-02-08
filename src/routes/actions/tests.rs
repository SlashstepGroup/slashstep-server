/**
 * 
 * Any test cases for /actions should be handled here.
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
use reqwest::StatusCode;
use crate::{
  AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, resources::{
    access_policy::{
      AccessPolicy, AccessPolicyPrincipalType, AccessPolicyResourceType, ActionPermissionLevel, IndividualPrincipal, InitialAccessPolicyProperties
    }, 
    action::{
      Action, 
      DEFAULT_ACTION_LIST_LIMIT
    }, 
   
  }, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody
};

/// Verifies that the router can return a 200 status code and the requested action list.
#[tokio::test]
async fn verify_returned_action_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actions.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.list" action to the user.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
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
  let response = test_server.get(&format!("/actions"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_json: ListResourcesResponseBody::<Action> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_action_count = Action::count("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_action_count);

  let actual_actions = Action::list("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_actions.len());

  for actual_action in actual_actions {

    let found_access_policy = response_json.resources.iter().find(|action| action.id == actual_action.id);
    assert!(found_access_policy.is_some());

  }

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_action_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actions.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.list" action to the user.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
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
  let query = format!("name ~ \"{}\"", "actions");
  let response = test_server.get(&format!("/actions"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_json: ListResourcesResponseBody::<Action> = response.json();
  let actual_action_count = Action::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_action_count);

  let actual_actions = Action::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_actions.len());

  for actual_action in actual_actions {

    let found_action = response_json.resources.iter().find(|action| action.id == actual_action.id);
    assert!(found_action.is_some());

  }

  return Ok(());

}

/// Verifies that there's a default access policy list limit.
#[tokio::test]
async fn verify_default_action_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actions.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.list" action to the user.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Create dummy actions.
  let action_count = Action::count("", &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_ACTION_LIST_LIMIT - action_count + 1) {

    test_environment.create_random_action(None).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/actions"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Action> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_action_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actions.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.list" action to the user.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
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
  let response = test_server.get(&format!("/actions"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_actions() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.actions.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.list" action to the user.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: list_actions_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
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

  let bad_requests = vec![
    test_server.get(&format!("/actions"))
      .add_query_param("query", format!("SELECT * FROM actions")),
    test_server.get(&format!("/actions"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/actions"))
      .add_query_param("query", format!("SELECT * FROM actions WHERE id = {}", get_actions_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/actions"))
      .add_query_param("query", format!("app_ied = {}", get_actions_action.id)),
    test_server.get(&format!("/actions"))
      .add_query_param("query", format!("1 = 1")),
  ];

  for request in unprocessable_entity_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  }

  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_listing_actions() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/actions"))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_actions() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create a user and a session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
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
  let response = test_server.get(&format!("/actions"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}