/**
 * 
 * Any test cases for /apps/{app_id}/app-credentials should be handled here.
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
use chrono::{DateTime, Duration, Utc};
use ntest::timeout;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::{ActionPermissionLevel, IndividualPrincipal}, action::Action, app_credential::{AppCredential, DEFAULT_APP_CREDENTIAL_LIST_LIMIT, InitialAppCredentialPropertiesForPredefinedScope},}, routes::apps::app_id::app_credentials::CreateAppCredentialResponseBody, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.appCredentials.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.appCredentials.list" action.
  let list_app_credentials_action = Action::get_by_name("slashstep.appCredentials.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app_credential.app_id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_body: ListResourcesResponseBody::<AppCredential> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("app_id = {}", quote_literal(&dummy_app_credential.app_id.to_string()));
  let actual_app_credential_count = AppCredential::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_app_credential_count);

  let actual_app_credentials = AppCredential::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_app_credentials.len());
  assert_eq!(response_body.resources[0].id, actual_app_credentials[0].id);
  assert_eq!(response_body.resources[0].id, dummy_app_credential.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.appCredentials.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.appCredentials.list" action.
  let list_app_credentials_action = Action::get_by_name("slashstep.appCredentials.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = {}", quote_literal(&dummy_app_credential.id.to_string()));
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app_credential.app_id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_body: ListResourcesResponseBody::<AppCredential> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("app_id = {} AND {}", quote_literal(&dummy_app_credential.app_id.to_string()), &additional_query);
  let actual_app_credential_count = AppCredential::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_app_credential_count);

  let actual_app_credentials = AppCredential::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_app_credentials.len());
  assert_eq!(response_body.resources[0].id, actual_app_credentials[0].id);
  assert_eq!(response_body.resources[0].id, dummy_app_credential.id);

  return Ok(());

}

/// Verifies that there's a default list limit.
#[tokio::test]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.appCredentials.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.appCredentials.list" action to the user.
  let list_app_credentials_action = Action::get_by_name("slashstep.appCredentials.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;
  let app_credential_count = AppCredential::count(format!("app_id = {}", quote_literal(&dummy_app.id.to_string())).as_str(), &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_APP_CREDENTIAL_LIST_LIMIT - app_credential_count + 1) {

    test_environment.create_random_app_credential(Some(&dummy_app.id)).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<AppCredential> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_APP_CREDENTIAL_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  
  // Grant access to the "slashstep.appCredentials.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.appCredentials.list" action to the user.
  let list_app_credentials_action = Action::get_by_name("slashstep.appCredentials.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_app_credentials_action.id, &ActionPermissionLevel::User).await?;

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
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
    .add_query_param("query", format!("limit {}", DEFAULT_APP_CREDENTIAL_LIST_LIMIT + 1))
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
  
  // Grant access to the "slashstep.appCredentials.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "slashstep.appCredentials.list" action to the user.
  let list_app_credentials_action = Action::get_by_name("slashstep.appCredentials.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_app_credentials_action.id, &ActionPermissionLevel::User).await?;

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
    test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
      .add_query_param("query", format!("SELECT * FROM app_credentials")),
    test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
      .add_query_param("query", format!("SELECT * FROM app_credentials WHERE id = {}", get_app_credentials_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
      .add_query_param("query", format!("app_ied = {}", get_app_credentials_action.id)),
    test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
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
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
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
  let response = test_server.get(&format!("/apps/{}/app-credentials", &dummy_app.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_APP_CREDENTIAL_LIST_LIMIT + 1))
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
  let response = test_server.get(&format!("/apps/{}/app-credentials", &Uuid::now_v7()))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

  return Ok(());

}

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;

  // Give the user access to the "slashstep.apps.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_app_credentials_action = Action::get_by_name("slashstep.appCredentials.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_app_credentials_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_app_credential_properties = InitialAppCredentialPropertiesForPredefinedScope {
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/app-credentials", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_app_credential_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  let response_app_credential: CreateAppCredentialResponseBody = response.json();
  assert_eq!(initial_app_credential_properties.description, response_app_credential.description);
  assert_eq!(initial_app_credential_properties.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), response_app_credential.expiration_date); // The API should truncate the expiration date to the nearest millisecond.

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
  let response = test_server.post(&format!("/apps/{}/app-credentials", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "description": Uuid::now_v7().to_string(),
      "expiration_date": "forever"
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
  let initial_app_credential_properties = InitialAppCredentialPropertiesForPredefinedScope {
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/app-credentials", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_app_credential_properties))
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
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_app_credential_properties = InitialAppCredentialPropertiesForPredefinedScope {
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/app-credentials", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_app_credential_properties))
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

  let initial_app_credential_properties = InitialAppCredentialPropertiesForPredefinedScope {
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
  };

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.post(&format!("/apps/{}/app-credentials", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_app_credential_properties))
    .await;
  
  assert_eq!(response.status_code(), 404);
  return Ok(());

}