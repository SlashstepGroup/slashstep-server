/**
 * 
 * Any test cases for /projects/{project_id}/views should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action::Action, configuration::{Configuration, EditableConfigurationProperties}, view::{DEFAULT_RESOURCE_LIST_LIMIT, InitialViewPropertiesWithPredefinedParent, View, ViewParentResourceType, ViewType}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

#[tokio::test]
async fn verify_successful_view_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "views.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_views_action = Action::get_by_name("views.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_views_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_project = test_environment.create_random_project().await?;
  let initial_view_properties = InitialViewPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    default_filter_query: Some("".to_string()),
    r#type: ViewType::List,
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/views", dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_view_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_view: View = response.json();
  assert_eq!(response_view.name, initial_view_properties.name);
  assert_eq!(response_view.display_name, initial_view_properties.display_name);
  assert_eq!(response_view.default_filter_query, initial_view_properties.default_filter_query);
  assert_eq!(response_view.description, initial_view_properties.description);
  assert_eq!(response_view.parent_resource_type, ViewParentResourceType::Project);
  assert_eq!(response_view.parent_project_id, Some(dummy_project.id));
  assert_eq!(response_view.parent_workspace_id, None);
  assert_eq!(response_view.r#type, initial_view_properties.r#type);

  return Ok(());
  
}

/// Verifies that the server returns a 422 status code when the view name is over the maximum length.
#[tokio::test]
async fn verify_view_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "views.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_views_action = Action::get_by_name("views.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_views_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_view_name_length_configuration = Configuration::get_by_name("views.maximumNameLength", &test_environment.database_pool).await?;
  maximum_view_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_view_properties = InitialViewPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/views", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_view_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the view display name is over the maximum length.
#[tokio::test]
async fn verify_view_display_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "views.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_views_action = Action::get_by_name("views.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_views_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_view_display_name_length_configuration = Configuration::get_by_name("views.maximumDisplayNameLength", &test_environment.database_pool).await?;
  maximum_view_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_view_properties = InitialViewPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/views", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_view_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the view description is over the maximum length.
#[tokio::test]
async fn verify_view_description_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "views.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_views_action = Action::get_by_name("views.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_views_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let maximum_view_description_length_configuration = Configuration::get_by_name("views.maximumDescriptionLength", &test_environment.database_pool).await?;
  maximum_view_description_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_view_properties = InitialViewPropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string().replace("-", ""),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/views", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_view_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the view name doesn't match the allowed regex pattern.
#[tokio::test]
async fn verify_view_name_matches_regex() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "views.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_views_action = Action::get_by_name("views.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_views_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let project = test_environment.create_random_project().await?;
  let allowed_view_name_regex_configuration = Configuration::get_by_name("views.allowedNameRegex", &test_environment.database_pool).await?;
  allowed_view_name_regex_configuration.update(&EditableConfigurationProperties {
    text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let initial_view_properties = InitialViewPropertiesWithPredefinedParent {
    name: "Invalid View Name With Spaces".to_string(),
    display_name: Uuid::now_v7().to_string(),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/views", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_view_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_view_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "views.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_views_action = Action::get_by_name("views.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_views_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "views.list" action.
  let list_views_action = Action::get_by_name("views.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_views_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_view = test_environment.create_random_view(Some(&ViewParentResourceType::Project), Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_views: ListResourcesResponseBody::<View> = response.json();
  assert_eq!(response_views.total_count, 1);
  assert_eq!(response_views.resources.len(), 1);

  let query = format!("parent_project_id = {}", quote_literal(&dummy_project.id.to_string()));
  let actual_view_count = View::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_views.total_count, actual_view_count);

  let actual_views = View::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_views.resources.len(), actual_views.len());
  assert_eq!(response_views.resources[0].id, actual_views[0].id);
  assert_eq!(response_views.resources[0].id, shown_view.id);

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
  
  // Give the user access to the "views.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_views_action = Action::get_by_name("views.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_views_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "views.list" action.
  let list_views_action = Action::get_by_name("views.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_views_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_view = test_environment.create_random_view(Some(&ViewParentResourceType::Project), Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_view.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_views: ListResourcesResponseBody::<View> = response.json();
  assert_eq!(response_views.total_count, 1);
  assert_eq!(response_views.resources.len(), 1);

  let query = format!("parent_project_id = {} AND ({})", quote_literal(&dummy_project.id.to_string()), additional_query);
  let actual_view_count = View::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_views.total_count, actual_view_count);

  let actual_views = View::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_views.resources.len(), actual_views.len());
  assert_eq!(response_views.resources[0].id, actual_views[0].id);
  assert_eq!(response_views.resources[0].id, shown_view.id);

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
  
  // Give the user access to the "views.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_views_action = Action::get_by_name("views.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_views_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "views.list" action.
  let list_views_action = Action::get_by_name("views.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_views_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let _ = test_environment.create_random_view(Some(&ViewParentResourceType::Project), Some(&dummy_project.id)).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<View> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_view_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_views_action = Action::get_by_name("views.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_views_action.id, &ActionPermissionLevel::User).await?;
  let list_views_action = Action::get_by_name("views.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_views_action.id, &ActionPermissionLevel::User).await?;

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
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_views() -> Result<(), TestSlashstepServerError> {

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
  let get_views_action = Action::get_by_name("views.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_views_action.id, &ActionPermissionLevel::User).await?;

  let list_views_action = Action::get_by_name("views.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_views_action.id, &ActionPermissionLevel::User).await?;

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
    test_server.get(&format!("/projects/{}/views", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM views")),
    test_server.get(&format!("/projects/{}/views", &dummy_project.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/projects/{}/views", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM views WHERE action_id = {}", get_views_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/projects/{}/views", &dummy_project.id))
      .add_query_param("query", format!("action_ied = {}", get_views_action.id)),
    test_server.get(&format!("/projects/{}/views", &dummy_project.id))
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
async fn verify_authentication_when_listing_views() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_views() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/views", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}