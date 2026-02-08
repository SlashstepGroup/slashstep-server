/**
 * 
 * Any test cases for /apps/{app_id}/actions should be handled here.
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
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPrincipalType, AccessPolicyResourceType, ActionPermissionLevel, IndividualPrincipal, InitialAccessPolicyProperties}, action::{Action, ActionParentResourceType, DEFAULT_ACTION_LIST_LIMIT, InitialActionPropertiesForPredefinedScope},}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;

  // Give the user access to the "slashstep.apps.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_actions_action = Action::get_by_name("slashstep.actions.create", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &create_actions_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  let response_action: Action = response.json();
  assert_eq!(initial_action_properties.name, response_action.name);
  assert_eq!(initial_action_properties.display_name, response_action.display_name);
  assert_eq!(initial_action_properties.description, response_action.description);
  assert_eq!(dummy_app.id, response_action.parent_app_id.expect("Parent app ID is not set."));
  assert_eq!(response_action.parent_resource_type, ActionParentResourceType::App);

  return Ok(());
  
}

/// Verifies that the server returns a 400 status code when the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_json_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "name": true,
      "display_name": "true",
      "description": false,
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested resource doesn't exist.
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.post(&format!("/apps/{}/actions", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.actions.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &get_actions_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.actions.list" action.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &list_actions_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;
  let dummy_action = test_environment.create_random_action(Some(&dummy_app.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_body: ListResourcesResponseBody::<Action> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("parent_app_id = {}", quote_literal(&dummy_app.id.to_string()));
  let actual_action_count = Action::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_action_count);

  let actual_access_policies = Action::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_access_policies.len());
  assert_eq!(response_body.resources[0].id, actual_access_policies[0].id);
  assert_eq!(response_body.resources[0].id, dummy_action.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.actions.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &get_actions_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.actions.list" action.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &list_actions_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;
  test_environment.create_random_action(Some(&dummy_app.id)).await?;
  let dummy_action = test_environment.create_random_action(Some(&dummy_app.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = {}", quote_literal(&dummy_action.id.to_string()));
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_body: ListResourcesResponseBody::<Action> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("parent_app_id = {} AND ({})", quote_literal(&dummy_app.id.to_string()), &additional_query);
  let actual_action_count = Action::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_action_count);

  let actual_actions = Action::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_actions.len());
  assert_eq!(response_body.resources[0].id, actual_actions[0].id);
  assert_eq!(response_body.resources[0].id, dummy_action.id);

  return Ok(());

}

/// Verifies that there's a default list limit.
#[tokio::test]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {

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

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;
  let action_count = Action::count(format!("parent_app_id = {}", quote_literal(&dummy_app.id.to_string())).as_str(), &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_ACTION_LIST_LIMIT - action_count + 1) {

    test_environment.create_random_action(Some(&dummy_app.id)).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
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
async fn verify_maximum_list_limit() -> Result<(), TestSlashstepServerError> {

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

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LIST_LIMIT + 1))
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

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
      .add_query_param("query", format!("SELECT * FROM actions")),
    test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
      .add_query_param("query", format!("SELECT * FROM actions WHERE id = {}", get_actions_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
      .add_query_param("query", format!("parenet_app_id = {}", get_actions_action.id)),
    test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
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

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
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
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
    .add_query_param("query", format!("limit {}", DEFAULT_ACTION_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}

/// Verifies that the server returns a 404 status code when the parent resource is not found.
#[tokio::test]
async fn verify_parent_resource_not_found_when_listing_resources() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/apps/{}/actions", &Uuid::now_v7()))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

  return Ok(());

}