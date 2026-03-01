/**
 * 
 * Any test cases for /items/{item_id}/field-values should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{ActionPermissionLevel, IndividualPrincipal}, action::Action, field::FieldValueType, field_value::{DEFAULT_RESOURCE_LIST_LIMIT, FieldValue, FieldValueParentResourceType, InitialFieldValueProperties, InitialFieldValuePropertiesWithPredefinedParent}, item::{InitialItemProperties, Item}}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

async fn create_field_value(test_environment: &TestEnvironment, item_id: &Uuid) -> Result<FieldValue, TestSlashstepServerError> {

  let dummy_field = test_environment.create_random_field().await?;
  let dummy_field_value = FieldValue::create(&InitialFieldValueProperties {
    parent_resource_type: FieldValueParentResourceType::Item,
    parent_item_id: Some(*item_id),
    field_id: dummy_field.id,
    value_type: FieldValueType::Text,
    text_value: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  return Ok(dummy_field_value);

}

#[tokio::test]
async fn verify_successful_field_value_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "fieldValues.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_field_values_action = Action::get_by_name("fieldValues.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let field = test_environment.create_random_field().await?;
  let dummy_item = Item::create(&InitialItemProperties {
    summary: Uuid::now_v7().to_string(),
    parent_project_id: field.parent_project_id,
    ..Default::default()
  }, &test_environment.database_pool).await?;
  let initial_field_value_properties = InitialFieldValuePropertiesWithPredefinedParent {
    field_id: field.id,
    value_type: FieldValueType::Text,
    text_value: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/items/{}/field-values", dummy_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_field_value_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_field_value: FieldValue = response.json();
  assert_eq!(response_field_value.field_id, initial_field_value_properties.field_id);
  assert_eq!(response_field_value.value_type, initial_field_value_properties.value_type);
  assert_eq!(response_field_value.text_value, initial_field_value_properties.text_value);
  assert_eq!(response_field_value.parent_resource_type, FieldValueParentResourceType::Item);
  assert_eq!(response_field_value.parent_item_id, Some(dummy_item.id));
  assert_eq!(response_field_value.parent_field_id, None);
  assert_eq!(response_field_value.number_value, None);
  assert_eq!(response_field_value.boolean_value, None);
  assert_eq!(response_field_value.timestamp_value, None);
  assert_eq!(response_field_value.stakeholder_type, None);
  assert_eq!(response_field_value.stakeholder_user_id, None);
  assert_eq!(response_field_value.stakeholder_group_id, None);
  assert_eq!(response_field_value.stakeholder_app_id, None);

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_field_value_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "fieldValues.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_values_action = Action::get_by_name("fieldValues.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "fieldValues.list" action.
  let list_field_values_action = Action::get_by_name("fieldValues.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_item = test_environment.create_random_item().await?;
  let shown_field_value = create_field_value(&test_environment, &dummy_item.id).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_field_values: ListResourcesResponseBody::<FieldValue> = response.json();
  assert_eq!(response_field_values.total_count, 1);
  assert_eq!(response_field_values.resources.len(), 1);

  let query = format!("parent_item_id = {}", quote_literal(&dummy_item.id.to_string()));
  let actual_field_value_count = FieldValue::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_field_values.total_count, actual_field_value_count);

  let actual_field_values = FieldValue::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_field_values.resources.len(), actual_field_values.len());
  assert_eq!(response_field_values.resources[0].id, actual_field_values[0].id);
  assert_eq!(response_field_values.resources[0].id, shown_field_value.id);

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
  
  // Give the user access to the "fieldValues.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_values_action = Action::get_by_name("fieldValues.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "fieldValues.list" action.
  let list_field_values_action = Action::get_by_name("fieldValues.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_item = test_environment.create_random_item().await?;
  let shown_field_value = create_field_value(&test_environment, &dummy_item.id).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_field_value.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_field_values: ListResourcesResponseBody::<FieldValue> = response.json();
  assert_eq!(response_field_values.total_count, 1);
  assert_eq!(response_field_values.resources.len(), 1);

  let query = format!("parent_item_id = {} AND {}", quote_literal(&dummy_item.id.to_string()), additional_query);
  let actual_field_value_count = FieldValue::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_field_values.total_count, actual_field_value_count);

  let actual_field_values = FieldValue::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_field_values.resources.len(), actual_field_values.len());
  assert_eq!(response_field_values.resources[0].id, actual_field_values[0].id);
  assert_eq!(response_field_values.resources[0].id, shown_field_value.id);

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
  
  // Give the user access to the "fieldValues.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_field_values_action = Action::get_by_name("fieldValues.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "fieldValues.list" action.
  let list_field_values_action = Action::get_by_name("fieldValues.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_item = test_environment.create_random_item().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let _ = create_field_value(&test_environment, &dummy_item.id).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<FieldValue> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_field_value_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_field_values_action = Action::get_by_name("fieldValues.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_values_action.id, &ActionPermissionLevel::User).await?;
  let list_field_values_action = Action::get_by_name("fieldValues.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_field_values() -> Result<(), TestSlashstepServerError> {

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
  let get_field_values_action = Action::get_by_name("fieldValues.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_field_values_action.id, &ActionPermissionLevel::User).await?;

  let list_field_values_action = Action::get_by_name("fieldValues.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_field_values_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
      .add_query_param("query", format!("SELECT * FROM field_values")),
    test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
      .add_query_param("query", format!("SELECT * FROM field_values WHERE action_id = {}", get_field_values_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
      .add_query_param("query", format!("action_ied = {}", get_field_values_action.id)),
    test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
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
async fn verify_authentication_when_listing_field_values() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let dummy_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_field_values() -> Result<(), TestSlashstepServerError> {

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
  let dummy_item = test_environment.create_random_item().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/items/{}/field-values", &dummy_item.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}