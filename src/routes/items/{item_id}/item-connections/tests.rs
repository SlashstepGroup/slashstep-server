/**
 * 
 * Any test cases for /items/{item_id}/item-connections should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{ActionPermissionLevel}, action::Action, item_connection::{DEFAULT_RESOURCE_LIST_LIMIT, InitialItemConnectionProperties, InitialItemConnectionPropertiesWithPredefinedOutwardItem, ItemConnection}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

async fn create_item_connection(test_environment: &TestEnvironment, outward_item_id: &Uuid, inward_item_id: &Uuid) -> Result<ItemConnection, TestSlashstepServerError> {

  let item_connection_type = test_environment.create_random_item_connection_type().await?;
  let dummy_item_connection = ItemConnection::create(&InitialItemConnectionProperties {
    item_connection_type_id: item_connection_type.id,
    inward_item_id: *inward_item_id,
    outward_item_id: *outward_item_id,
  }, &test_environment.database_pool).await?;

  return Ok(dummy_item_connection);

}

#[tokio::test]
async fn verify_successful_item_connection_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "itemConnections.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_item_connections_action = Action::get_by_name("itemConnections.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_item_connection_type = test_environment.create_random_item_connection_type().await?;
  let outward_item = test_environment.create_random_item().await?;
  let inward_item = test_environment.create_random_item().await?;
  let initial_item_connection_properties = InitialItemConnectionPropertiesWithPredefinedOutwardItem {
    inward_item_id: inward_item.id,
    item_connection_type_id: dummy_item_connection_type.id
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.post(&format!("/items/{}/item-connections", outward_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_item_connection_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_item_connection: ItemConnection = response.json();
  assert_eq!(response_item_connection.item_connection_type_id, dummy_item_connection_type.id);
  assert_eq!(response_item_connection.inward_item_id, inward_item.id);
  assert_eq!(response_item_connection.outward_item_id, outward_item.id);

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_item_connection_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "itemConnections.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_connections_action = Action::get_by_name("itemConnections.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemConnections.list" action.
  let list_item_connections_action = Action::get_by_name("itemConnections.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let outward_item = test_environment.create_random_item().await?;
  let inward_item = test_environment.create_random_item().await?;
  let shown_item_connection = create_item_connection(&test_environment, &outward_item.id, &inward_item.id).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_connections: ListResourcesResponseBody::<ItemConnection> = response.json();
  assert_eq!(response_item_connections.total_count, 1);
  assert_eq!(response_item_connections.resources.len(), 1);

  let query = format!("(outward_item_id = {} OR inward_item_id = {})", quote_literal(&outward_item.id.to_string()), quote_literal(&outward_item.id.to_string()));
  let actual_item_connection_count = ItemConnection::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_connections.total_count, actual_item_connection_count);

  let actual_item_connections = ItemConnection::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_connections.resources.len(), actual_item_connections.len());
  assert_eq!(response_item_connections.resources[0].id, actual_item_connections[0].id);
  assert_eq!(response_item_connections.resources[0].id, shown_item_connection.id);

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
  
  // Give the user access to the "itemConnections.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_connections_action = Action::get_by_name("itemConnections.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemConnections.list" action.
  let list_item_connections_action = Action::get_by_name("itemConnections.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let outward_item = test_environment.create_random_item().await?;
  let inward_item = test_environment.create_random_item().await?;
  let shown_item_connection = create_item_connection(&test_environment, &outward_item.id, &inward_item.id).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_item_connection.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_connections: ListResourcesResponseBody::<ItemConnection> = response.json();
  assert_eq!(response_item_connections.total_count, 1);
  assert_eq!(response_item_connections.resources.len(), 1);

  // The outward item ID is used for the inward item ID in the query 
  // because the router should return item connections where 
  // the item is either the inward item or the outward item.
  //
  // We know the inward item ID because we defined it in this test, but users might not.
  let query = format!("(outward_item_id = {} OR inward_item_id = {}) AND {}", quote_literal(&outward_item.id.to_string()), quote_literal(&outward_item.id.to_string()), additional_query);
  let actual_item_connection_count = ItemConnection::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_connections.total_count, actual_item_connection_count);

  let actual_item_connections = ItemConnection::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_connections.resources.len(), actual_item_connections.len());
  assert_eq!(response_item_connections.resources[0].id, actual_item_connections[0].id);
  assert_eq!(response_item_connections.resources[0].id, shown_item_connection.id);

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
  
  // Give the user access to the "itemConnections.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_connections_action = Action::get_by_name("itemConnections.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemConnections.list" action.
  let list_item_connections_action = Action::get_by_name("itemConnections.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let outward_item = test_environment.create_random_item().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let inward_item = test_environment.create_random_item().await?;
    let _ = create_item_connection(&test_environment, &outward_item.id, &inward_item.id).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<ItemConnection> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_item_connection_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_item_connections_action = Action::get_by_name("itemConnections.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_connections_action.id, &ActionPermissionLevel::User).await?;
  let list_item_connections_action = Action::get_by_name("itemConnections.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let outward_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_item_connections() -> Result<(), TestSlashstepServerError> {

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
  let get_item_connections_action = Action::get_by_name("itemConnections.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_connections_action.id, &ActionPermissionLevel::User).await?;

  let list_item_connections_action = Action::get_by_name("itemConnections.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_connections_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let outward_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let bad_requests = vec![
    test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
      .add_query_param("query", format!("SELECT * FROM item_connections")),
    test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
      .add_query_param("query", format!("SELECT * FROM item_connections WHERE action_id = {}", get_item_connections_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
      .add_query_param("query", format!("action_ied = {}", get_item_connections_action.id)),
    test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
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
async fn verify_authentication_when_listing_item_connections() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let outward_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_item_connections() -> Result<(), TestSlashstepServerError> {

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
  let outward_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/items/{}/item-connections", &outward_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}