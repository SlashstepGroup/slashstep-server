/**
 * 
 * Any test cases for /projects/{project_id}/iterations should be handled here.
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
use chrono::DateTime;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action::Action, configuration::{Configuration, EditableConfigurationProperties}, iteration::{DEFAULT_RESOURCE_LIST_LIMIT, InitialIterationPropertiesWithPredefinedParent, Iteration}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

#[tokio::test]
async fn verify_successful_iteration_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "iterations.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_iterations_action = Action::get_by_name("iterations.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_project = test_environment.create_random_project().await?;
  let initial_iteration_properties = InitialIterationPropertiesWithPredefinedParent {
    display_name: Uuid::now_v7().to_string(),
    start_date: chrono::Utc::now(),
    end_date: chrono::Utc::now() + chrono::Duration::days(7),
    actual_start_date: Some(chrono::Utc::now() + chrono::Duration::days(1)),
    actual_end_date: Some(chrono::Utc::now() + chrono::Duration::days(2))
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/iterations", dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_iteration_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_iteration: Iteration = response.json();
  assert_eq!(response_iteration.display_name, initial_iteration_properties.display_name);
  assert_eq!(
    DateTime::from_timestamp_millis(response_iteration.start_date.timestamp_millis()), 
    DateTime::from_timestamp_millis(initial_iteration_properties.start_date.timestamp_millis())
  );
  assert_eq!(
    DateTime::from_timestamp_millis(response_iteration.end_date.timestamp_millis()), 
    DateTime::from_timestamp_millis(initial_iteration_properties.end_date.timestamp_millis())
  );
  assert_eq!(
    DateTime::from_timestamp_millis(response_iteration.actual_start_date.expect("Expected an updated actual start date.").timestamp_millis()), 
    DateTime::from_timestamp_millis(initial_iteration_properties.actual_start_date.expect("Expected an updated actual start date.").timestamp_millis())
  );
  assert_eq!(
    DateTime::from_timestamp_millis(response_iteration.actual_end_date.expect("Expected an updated actual end date.").timestamp_millis()), 
    DateTime::from_timestamp_millis(initial_iteration_properties.actual_end_date.expect("Expected an updated actual end date.").timestamp_millis())
  );

  return Ok(());
  
}

/// Verifies that the server returns a 422 status code when the iteration display name is over the maximum length.
#[tokio::test]
async fn verify_iteration_display_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "iterations.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_iterations_action = Action::get_by_name("iterations.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_iteration_display_name_length_configuration = Configuration::get_by_name("iterations.maximumDisplayNameLength", &test_environment.database_pool).await?;
  maximum_iteration_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_iteration_properties = InitialIterationPropertiesWithPredefinedParent {
    display_name: Uuid::now_v7().to_string(),
    start_date: chrono::Utc::now(),
    end_date: chrono::Utc::now() + chrono::Duration::days(7),
    actual_start_date: Some(chrono::Utc::now() + chrono::Duration::days(1)),
    actual_end_date: Some(chrono::Utc::now() + chrono::Duration::days(2))
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/iterations", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_iteration_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_iteration_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "iterations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_iterations_action = Action::get_by_name("iterations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "iterations.list" action.
  let list_iterations_action = Action::get_by_name("iterations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_iteration = test_environment.create_random_iteration(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_iterations: ListResourcesResponseBody::<Iteration> = response.json();
  assert_eq!(response_iterations.total_count, 1);
  assert_eq!(response_iterations.resources.len(), 1);

  let query = format!("parent_project_id = {}", quote_literal(&dummy_project.id.to_string()));
  let actual_iteration_count = Iteration::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_iterations.total_count, actual_iteration_count);

  let actual_iterations = Iteration::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_iterations.resources.len(), actual_iterations.len());
  assert_eq!(response_iterations.resources[0].id, actual_iterations[0].id);
  assert_eq!(response_iterations.resources[0].id, shown_iteration.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_resource_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "iterations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_iterations_action = Action::get_by_name("iterations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "iterations.list" action.
  let list_iterations_action = Action::get_by_name("iterations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_iteration = test_environment.create_random_iteration(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_iteration.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_iterations: ListResourcesResponseBody::<Iteration> = response.json();
  assert_eq!(response_iterations.total_count, 1);
  assert_eq!(response_iterations.resources.len(), 1);

  let query = format!("parent_project_id = {} AND ({})", quote_literal(&dummy_project.id.to_string()), additional_query);
  let actual_iteration_count = Iteration::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_iterations.total_count, actual_iteration_count);

  let actual_iterations = Iteration::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_iterations.resources.len(), actual_iterations.len());
  assert_eq!(response_iterations.resources[0].id, actual_iterations[0].id);
  assert_eq!(response_iterations.resources[0].id, shown_iteration.id);

  return Ok(());

}

/// Verifies that the default access policy list limit is enforced.
#[tokio::test]
async fn verify_default_resource_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "iterations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_iterations_action = Action::get_by_name("iterations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "iterations.list" action.
  let list_iterations_action = Action::get_by_name("iterations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let _ = test_environment.create_random_iteration(Some(&dummy_project.id)).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Iteration> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_iteration_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_iterations_action = Action::get_by_name("iterations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_iterations_action.id, &ActionPermissionLevel::User).await?;
  let list_iterations_action = Action::get_by_name("iterations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_iterations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_iterations_action = Action::get_by_name("iterations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_iterations_action.id, &ActionPermissionLevel::User).await?;

  let list_iterations_action = Action::get_by_name("iterations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_iterations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let bad_requests = vec![
    test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM iterations")),
    test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM iterations WHERE action_id = {}", get_iterations_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
      .add_query_param("query", format!("action_ied = {}", get_iterations_action.id)),
    test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
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
async fn verify_authentication_when_listing_iterations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_iterations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Create a dummy action.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/iterations", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}