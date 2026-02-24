/**
 * 
 * Any test cases for /field-choices should be handled here.
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
  AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, initialize_predefined_configurations, 
    initialize_predefined_roles
  }, resources::{
    access_policy::{
      ActionPermissionLevel, IndividualPrincipal
    }, action::Action, field_choice::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, FieldChoice},
  }, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody
};

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Grant access to the "slashstep.fieldChoices.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_choices_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.fieldChoices.list" action to the user.
  let list_field_choices_action = Action::get_by_name("slashstep.fieldChoices.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy delegation policy.
  test_environment.create_random_field_choice(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/field-choices"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<FieldChoice> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_field_choice_count = FieldChoice::count("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_field_choice_count);

  let actual_field_choices = FieldChoice::list("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_field_choices.len());

  for actual_field_choice in actual_field_choices {

    let found_access_policy = response_json.resources.iter().find(|field_choice| field_choice.id == actual_field_choice.id);
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
  
  // Grant access to the "slashstep.apps.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_choices_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.apps.list" action to the user.
  let list_field_choices_action = Action::get_by_name("slashstep.fieldChoices.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy delegation policy.
  let dummy_field_choice = test_environment.create_random_field_choice(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let query = format!("id = {}", quote_literal(&dummy_field_choice.id.to_string()));
  let response = test_server.get(&format!("/field-choices"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_json: ListResourcesResponseBody::<FieldChoice> = response.json();
  assert!(response_json.total_count > 0);
  assert!(response_json.resources.len() > 0);

  let actual_field_choice_count = FieldChoice::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.total_count, actual_field_choice_count);

  let actual_field_choices = FieldChoice::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_json.resources.len(), actual_field_choices.len());

  for actual_field_choice in actual_field_choices {

    let found_action = response_json.resources.iter().find(|field_choice| field_choice.id == actual_field_choice.id);
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.fieldChoices.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_choices_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.fieldChoices.list" action to the user.
  let list_field_choices_action = Action::get_by_name("slashstep.fieldChoices.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy delegation policies.
  let field_choice_count = FieldChoice::count("", &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - field_choice_count + 1) {

    test_environment.create_random_field_choice(None).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/field-choices"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<FieldChoice> = response.json();
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
  
  // Grant access to the "slashstep.fieldChoices.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_choices_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.apps.list" action to the user.
  let list_field_choices_action = Action::get_by_name("slashstep.fieldChoices.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/field-choices"))
    .add_query_param("query", format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
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
  
  // Grant access to the "slashstep.fieldChoices.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_choices_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.fieldChoices.list" action to the user.
  let list_field_choices_action = Action::get_by_name("slashstep.fieldChoices.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_choices_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/field-choices"))
      .add_query_param("query", format!("id ~ {}", quote_literal(&get_field_choices_action.id.to_string()))),
    test_server.get(&format!("/field-choices"))
      .add_query_param("query", format!("SELECT * FROM field_choices")),
    test_server.get(&format!("/field-choices"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/field-choices"))
      .add_query_param("query", format!("id = null; SELECT * FROM field_choices WHERE id = {}", quote_literal(&get_field_choices_action.id.to_string())))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/field-choices"))
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
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/field-choices"))
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
  let response = test_server.get(&format!("/field-choices"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}