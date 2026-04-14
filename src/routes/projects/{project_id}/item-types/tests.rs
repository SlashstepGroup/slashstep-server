/**
 * 
 * Any test cases for /projects/{project_id}/item-types should be handled here.
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
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action::Action, item_type::{DEFAULT_RESOURCE_LIST_LIMIT, InitialItemTypePropertiesWithPredefinedParent, ItemType}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

#[tokio::test]
async fn verify_successful_item_type_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "itemTypes.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_item_types_action = Action::get_by_name("itemTypes.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_project = test_environment.create_random_project().await?;
  let initial_item_type_properties = InitialItemTypePropertiesWithPredefinedParent {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    item_type_icon_id: None
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/projects/{}/item-types", dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_item_type_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_item_type: ItemType = response.json();
  assert_eq!(response_item_type.name, initial_item_type_properties.name);
  assert_eq!(response_item_type.display_name, initial_item_type_properties.display_name);
  assert_eq!(response_item_type.description, initial_item_type_properties.description);
  assert_eq!(response_item_type.item_type_icon_id, initial_item_type_properties.item_type_icon_id);
  assert_eq!(response_item_type.parent_project_id, dummy_project.id);

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_item_type_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "itemTypes.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_types_action = Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypes.list" action.
  let list_item_types_action = Action::get_by_name("itemTypes.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_item_type = test_environment.create_random_item_type(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_types: ListResourcesResponseBody::<ItemType> = response.json();
  assert_eq!(response_item_types.total_count, 1);
  assert_eq!(response_item_types.resources.len(), 1);

  let query = format!("parent_project_id = {}", quote_literal(&dummy_project.id.to_string()));
  let actual_item_type_count = ItemType::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_types.total_count, actual_item_type_count);

  let actual_item_types = ItemType::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_types.resources.len(), actual_item_types.len());
  assert_eq!(response_item_types.resources[0].id, actual_item_types[0].id);
  assert_eq!(response_item_types.resources[0].id, shown_item_type.id);

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
  
  // Give the user access to the "itemTypes.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_types_action = Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypes.list" action.
  let list_item_types_action = Action::get_by_name("itemTypes.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_item_type = test_environment.create_random_item_type(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_item_type.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_types: ListResourcesResponseBody::<ItemType> = response.json();
  assert_eq!(response_item_types.total_count, 1);
  assert_eq!(response_item_types.resources.len(), 1);

  let query = format!("parent_project_id = {} AND ({})", quote_literal(&dummy_project.id.to_string()), additional_query);
  let actual_item_type_count = ItemType::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_types.total_count, actual_item_type_count);

  let actual_item_types = ItemType::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_types.resources.len(), actual_item_types.len());
  assert_eq!(response_item_types.resources[0].id, actual_item_types[0].id);
  assert_eq!(response_item_types.resources[0].id, shown_item_type.id);

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
  
  // Give the user access to the "itemTypes.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_types_action = Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypes.list" action.
  let list_item_types_action = Action::get_by_name("itemTypes.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_types_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    test_environment.create_random_item_type(Some(&dummy_project.id)).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<ItemType> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_item_type_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_item_types_action = Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_types_action.id, &ActionPermissionLevel::User).await?;
  let list_item_types_action = Action::get_by_name("itemTypes.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_types_action.id, &ActionPermissionLevel::User).await?;

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
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_item_types() -> Result<(), TestSlashstepServerError> {

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
  let get_item_types_action = Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_types_action.id, &ActionPermissionLevel::User).await?;

  let list_item_types_action = Action::get_by_name("itemTypes.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_types_action.id, &ActionPermissionLevel::User).await?;

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
    test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM item_types")),
    test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM item_types WHERE action_id = {}", get_item_types_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
      .add_query_param("query", format!("action_ied = {}", get_item_types_action.id)),
    test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
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
async fn verify_authentication_when_listing_item_types() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_item_types() -> Result<(), TestSlashstepServerError> {

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
  let response = test_server.get(&format!("/projects/{}/item-types", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}