/**
 * 
 * Any test cases for /projects/{project_id}/statuses should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action::Action, configuration::{Configuration, EditableConfigurationProperties}, status::{DEFAULT_RESOURCE_LIST_LIMIT, InitialStatusPropertiesWithPredefinedParent, Status, StatusType}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

#[tokio::test]
async fn verify_successful_status_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "statuses.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_statuses_action = Action::get_by_name("statuses.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_project = test_environment.create_random_project().await?;
  let initial_status_properties = InitialStatusPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    r#type: StatusType::ToDo,
    decimal_color: None,
    next_status_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/statuses", dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_status_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_status: Status = response.json();
  assert_eq!(response_status.name, initial_status_properties.name);
  assert_eq!(response_status.display_name, initial_status_properties.display_name);
  assert_eq!(response_status.description, initial_status_properties.description);
  assert_eq!(response_status.parent_project_id, dummy_project.id);
  assert_eq!(response_status.r#type, initial_status_properties.r#type);
  assert_eq!(response_status.decimal_color, initial_status_properties.decimal_color);
  assert_eq!(response_status.next_status_id, initial_status_properties.next_status_id);

  return Ok(());
  
}

/// Verifies that the server returns a 422 status code when the status name is over the maximum length.
#[tokio::test]
async fn verify_status_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "statuses.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_statuses_action = Action::get_by_name("statuses.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_status_name_length_configuration = Configuration::get_by_name("statuses.maximumNameLength", &test_environment.database_pool).await?;
  maximum_status_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_status_properties = InitialStatusPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    r#type: StatusType::ToDo,
    decimal_color: None,
    description: None,
    next_status_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/statuses", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_status_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the status display name is over the maximum length.
#[tokio::test]
async fn verify_status_display_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "statuses.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_statuses_action = Action::get_by_name("statuses.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_status_display_name_length_configuration = Configuration::get_by_name("statuses.maximumDisplayNameLength", &test_environment.database_pool).await?;
  maximum_status_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_status_properties = InitialStatusPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    r#type: StatusType::ToDo,
    decimal_color: None,
    description: None,
    next_status_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/statuses", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_status_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the status description is over the maximum length.
#[tokio::test]
async fn verify_status_description_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "statuses.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_statuses_action = Action::get_by_name("statuses.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_status_description_length_configuration = Configuration::get_by_name("statuses.maximumDescriptionLength", &test_environment.database_pool).await?;
  maximum_status_description_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_status_properties = InitialStatusPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    r#type: StatusType::ToDo,
    decimal_color: None,
    description: Some(Uuid::now_v7().to_string()),
    next_status_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/statuses", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_status_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the status name doesn't match the allowed regex pattern.
#[tokio::test]
async fn verify_status_name_matches_regex() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "statuses.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_statuses_action = Action::get_by_name("statuses.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let allowed_status_name_regex_configuration = Configuration::get_by_name("statuses.allowedNameRegex", &test_environment.database_pool).await?;
  allowed_status_name_regex_configuration.update(&EditableConfigurationProperties {
    text_value: Some("^$".to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_status_properties = InitialStatusPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    r#type: StatusType::ToDo,
    decimal_color: None,
    description: None,
    next_status_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/statuses", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_status_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_status_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "statuses.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_statuses_action = Action::get_by_name("statuses.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "statuses.list" action.
  let list_statuses_action = Action::get_by_name("statuses.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_status = test_environment.create_random_status(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_statuses: ListResourcesResponseBody::<Status> = response.json();
  assert_eq!(response_statuses.total_count, 1);
  assert_eq!(response_statuses.resources.len(), 1);

  let query = format!("parent_project_id = {}", quote_literal(&dummy_project.id.to_string()));
  let actual_status_count = Status::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_statuses.total_count, actual_status_count);

  let actual_statuses = Status::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_statuses.resources.len(), actual_statuses.len());
  assert_eq!(response_statuses.resources[0].id, actual_statuses[0].id);
  assert_eq!(response_statuses.resources[0].id, shown_status.id);

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
  
  // Give the user access to the "statuses.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_statuses_action = Action::get_by_name("statuses.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "statuses.list" action.
  let list_statuses_action = Action::get_by_name("statuses.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_status = test_environment.create_random_status(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_status.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_statuses: ListResourcesResponseBody::<Status> = response.json();
  assert_eq!(response_statuses.total_count, 1);
  assert_eq!(response_statuses.resources.len(), 1);

  let query = format!("parent_project_id = {} AND ({})", quote_literal(&dummy_project.id.to_string()), additional_query);
  let actual_status_count = Status::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_statuses.total_count, actual_status_count);

  let actual_statuses = Status::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_statuses.resources.len(), actual_statuses.len());
  assert_eq!(response_statuses.resources[0].id, actual_statuses[0].id);
  assert_eq!(response_statuses.resources[0].id, shown_status.id);

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
  
  // Give the user access to the "statuses.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_statuses_action = Action::get_by_name("statuses.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "statuses.list" action.
  let list_statuses_action = Action::get_by_name("statuses.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_statuses_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let _ = test_environment.create_random_status(Some(&dummy_project.id)).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Status> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_status_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_statuses_action = Action::get_by_name("statuses.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_statuses_action.id, &ActionPermissionLevel::User).await?;
  let list_statuses_action = Action::get_by_name("statuses.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_statuses_action.id, &ActionPermissionLevel::User).await?;

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
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_statuses() -> Result<(), TestSlashstepServerError> {

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
  let get_statuses_action = Action::get_by_name("statuses.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_statuses_action.id, &ActionPermissionLevel::User).await?;

  let list_statuses_action = Action::get_by_name("statuses.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_statuses_action.id, &ActionPermissionLevel::User).await?;

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
    test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM statuses")),
    test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM statuses WHERE action_id = {}", get_statuses_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
      .add_query_param("query", format!("action_ied = {}", get_statuses_action.id)),
    test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
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
async fn verify_authentication_when_listing_statuses() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_statuses() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/statuses", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}