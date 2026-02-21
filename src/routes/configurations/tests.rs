/**
 * 
 * Any test cases for /configurations should be handled here.
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
      ActionPermissionLevel,
      IndividualPrincipal
    }, action::Action, configuration::{self, Configuration},
  }, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody
};

/// Verifies that the router can return a 200 status code and the requested resource list.
#[tokio::test]
async fn verify_returned_resource_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.configurations.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.configurations.list" action to the user.
  let list_configurations_action = Action::get_by_name("slashstep.configurations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  test_environment.create_random_configuration().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/configurations"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Configuration> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_configuration_count = Configuration::count("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_configuration_count);

  let actual_configurations = Configuration::list("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_configurations.len());

  for actual_configuration in actual_configurations {

    let found_access_policy = response_json.resources.iter().find(|configuration| configuration.id == actual_configuration.id);
    assert!(found_access_policy.is_some());

  }

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested resource list.
#[tokio::test]
async fn verify_returned_resource_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.configurations.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.configurations.list" action to the user.
  let list_configurations_action = Action::get_by_name("slashstep.configurations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  test_environment.create_random_configuration().await?;
  let dummy_configuration = test_environment.create_random_configuration().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let query = format!("id = \"{}\"", dummy_configuration.id);
  let response = test_server.get(&format!("/configurations"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<Configuration> = response.json();
  let actual_configuration_count = Configuration::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_configuration_count);

  let actual_configurations = Configuration::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_configurations.len());

  for actual_configuration in actual_configurations {

    let found_configuration = response_json.resources.iter().find(|configuration| configuration.id == actual_configuration.id);
    assert!(found_configuration.is_some());

  }

  return Ok(());

}

/// Verifies that there's a default resource list limit.
#[tokio::test]
async fn verify_default_resource_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.configurations.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.configurations.list" action to the user.
  let list_configurations_action = Action::get_by_name("slashstep.configurations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy actions.
  let configuration_count = Configuration::count("", &test_environment.database_pool, None).await?;
  for _ in 0..(configuration::DEFAULT_RESOURCE_LIST_LIMIT - configuration_count + 1) {

    test_environment.create_random_configuration().await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/configurations"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Configuration> = response.json();
  assert_eq!(response_body.resources.len(), configuration::DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_resource_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.configurations.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.configurations.list" action to the user.
  let list_configurations_action = Action::get_by_name("slashstep.configurations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/configurations"))
    .add_query_param("query", format!("LIMIT {}", configuration::DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_resources() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.configurations.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.configurations.list" action to the user.
  let list_configurations_action = Action::get_by_name("slashstep.configurations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/configurations"))
      .add_query_param("query", format!("SELECT * FROM configurations")),
    test_server.get(&format!("/configurations"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/configurations"))
      .add_query_param("query", format!("SELECT * FROM configurations WHERE id = {}", get_configurations_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/configurations"))
      .add_query_param("query", format!("app_ied = {}", get_configurations_action.id)),
    test_server.get(&format!("/configurations"))
      .add_query_param("query", format!("1 = 1"))
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
async fn verify_authentication_when_listing_resources() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/configurations"))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_resources() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create a user and a session.
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
  let response = test_server.get(&format!("/configurations"))
    .add_query_param("query", format!("limit {}", configuration::DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}