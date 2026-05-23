/**
 * 
 * Any test cases for /roles should be handled here.
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
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::{
  AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_groups, initialize_predefined_roles
  }, resources::{
    access_policy::{
      AccessPolicyPrincipalType, PermissionLevel
    }, action::Action, configuration::{Configuration, EditableConfigurationProperties}, role::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, Role}
  }, routes::{ListResourcesResponseBody, roles::CreateRoleRequestBody}, tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Grant access to the "roles.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_delegation_policies_action = Action::get_by_name("roles.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Grant access to the "roles.list" action to the user.
  let list_delegation_policies_action = Action::get_by_name("roles.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Create a dummy role.
  test_environment.create_random_role(None, None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/roles"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Role> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.data.len() > 0);

  let actual_role_count = Role::count("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.total_count, actual_role_count);

  let actual_delegation_policies = Role::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.data.len(), actual_delegation_policies.len());

  for actual_role in actual_delegation_policies {

    let found_access_policy = response_json.data.iter().find(|role| role.id == actual_role.id);
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
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "apps.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_delegation_policies_action = Action::get_by_name("roles.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Grant access to the "apps.list" action to the user.
  let list_delegation_policies_action = Action::get_by_name("roles.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Create a dummy role.
  let dummy_role = test_environment.create_random_role(None, None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let query = format!("id = {}", quote_literal(&dummy_role.id.to_string()));
  let response = test_server.get(&format!("/roles"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Role> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.data.len() > 0);

  let actual_role_count = Role::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.total_count, actual_role_count);

  let actual_delegation_policies = Role::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_json.data.len(), actual_delegation_policies.len());

  for actual_role in actual_delegation_policies {

    let found_action = response_json.data.iter().find(|role| role.id == actual_role.id);
    assert!(found_action.is_some());

  }

  return Ok(());

}

/// Verifies that there's a default list limit.
#[tokio::test]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "roles.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_delegation_policies_action = Action::get_by_name("roles.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Grant access to the "roles.list" action to the user.
  let list_delegation_policies_action = Action::get_by_name("roles.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Create dummy roles.
  let role_count = Role::count("", &test_environment.database_pool, None, None).await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - role_count + 1) {

    test_environment.create_random_role(None, None).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/roles"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Role> = response.json();
  assert_eq!(response_body.data.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "roles.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_delegation_policies_action = Action::get_by_name("roles.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Grant access to the "apps.list" action to the user.
  let list_delegation_policies_action = Action::get_by_name("roles.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/roles"))
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
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "roles.get" action to the user.
  let plain_text_password = Uuid::now_v7().to_string();
  let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let get_delegation_policies_action = Action::get_by_name("roles.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Grant access to the "roles.list" action to the user.
  let list_delegation_policies_action = Action::get_by_name("roles.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_delegation_policies_action.id, &PermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let bad_requests = vec![
    test_server.get(&format!("/roles"))
      .add_query_param("query", format!("id ~ {}", quote_literal(&get_delegation_policies_action.id.to_string()))),
    test_server.get(&format!("/roles"))
      .add_query_param("query", format!("SELECT * FROM delegation_policies")),
    test_server.get(&format!("/roles"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/roles"))
      .add_query_param("query", format!("id = null; SELECT * FROM delegation_policies WHERE id = {}", quote_literal(&get_delegation_policies_action.id.to_string())))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/roles"))
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
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/roles"))
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
  initialize_predefined_groups(&test_environment.database_pool).await?;
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
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/roles"))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}

/// Verifies that the server can create a role and return a 201 status code.
#[tokio::test]
async fn verify_successful_role_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "workspaces.create" action.
  let user = test_environment.create_random_user(None).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let initial_workspace_properties = CreateRoleRequestBody {
    name: Uuid::now_v7().to_string().replace("-", ""),
    description: Some(Uuid::now_v7().to_string()),
    display_name: Uuid::now_v7().to_string(),
  };

  let create_roles_action = Action::get_by_name("roles.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_roles_action.id, &PermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/roles"))
    .json(&serde_json::json!(initial_workspace_properties))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_workspace: Role = response.json();
  assert_eq!(initial_workspace_properties.name, response_workspace.name);
  assert_eq!(initial_workspace_properties.description, response_workspace.description);
  assert_eq!(initial_workspace_properties.display_name, response_workspace.display_name);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the role name is over the maximum length.
#[tokio::test]
async fn verify_role_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let user = test_environment.create_random_user(None).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let initial_role_properties = CreateRoleRequestBody {
    name: Uuid::now_v7().to_string().replace("-", ""),
    description: Some(Uuid::now_v7().to_string()),
    display_name: Uuid::now_v7().to_string(),
  };

  let create_roles_action = Action::get_by_name("roles.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_roles_action.id, &PermissionLevel::User).await?;

  let maximum_name_length_configuration = Configuration::get_by_name("roles.maximumNameLength", &test_environment.database_pool).await?;
  maximum_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/roles"))
    .json(&serde_json::json!(initial_role_properties))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the role display name is over the maximum length.
#[tokio::test]
async fn verify_role_display_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let user = test_environment.create_random_user(None).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let initial_role_properties = CreateRoleRequestBody {
    name: Uuid::now_v7().to_string().replace("-", ""),
    description: Some(Uuid::now_v7().to_string()),
    display_name: Uuid::now_v7().to_string(),
  };

  let create_roles_action = Action::get_by_name("roles.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_roles_action.id, &PermissionLevel::User).await?;

  let maximum_display_name_length_configuration = Configuration::get_by_name("roles.maximumDisplayNameLength", &test_environment.database_pool).await?;
  maximum_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/roles"))
    .json(&serde_json::json!(initial_role_properties))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the role description is over the maximum length.
#[tokio::test]
async fn verify_role_description_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let user = test_environment.create_random_user(None).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let initial_role_properties = CreateRoleRequestBody {
    name: Uuid::now_v7().to_string().replace("-", ""),
    description: Some(Uuid::now_v7().to_string()),
    display_name: Uuid::now_v7().to_string(),
  };

  let create_roles_action = Action::get_by_name("roles.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_roles_action.id, &PermissionLevel::User).await?;

  let maximum_description_length_configuration = Configuration::get_by_name("roles.maximumDescriptionLength", &test_environment.database_pool).await?;
  maximum_description_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/roles"))
    .json(&serde_json::json!(initial_role_properties))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the role name doesn't match the allowed regex pattern.
#[tokio::test]
async fn verify_role_name_matches_regex() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_groups(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let user = test_environment.create_random_user(None).await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
  let initial_role_properties = CreateRoleRequestBody {
    name: Uuid::now_v7().to_string().replace("-", ""),
    description: Some(Uuid::now_v7().to_string()),
    display_name: Uuid::now_v7().to_string(),
  };

  let create_roles_action = Action::get_by_name("roles.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_roles_action.id, &PermissionLevel::User).await?;

  let allowed_name_regex_configuration = Configuration::get_by_name("roles.allowedNameRegex", &test_environment.database_pool).await?;
  allowed_name_regex_configuration.update(&EditableConfigurationProperties {
    text_value: Some("^$".to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
    redis_pool: test_environment.redis_pool.clone()
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/roles"))
    .json(&serde_json::json!(initial_role_properties))
    .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}
