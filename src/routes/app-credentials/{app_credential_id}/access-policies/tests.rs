/**
 * 
 * Any test cases for /app-credentials/{app_credential_id}/access-policies should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPrincipalType, ActionPermissionLevel, DEFAULT_ACCESS_POLICY_LIST_LIMIT, IndividualPrincipal, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action::Action,}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

async fn create_app_credential_access_policy(database_pool: &deadpool_postgres::Pool, scoped_app_credential_id: &Uuid, user_id: &Uuid, action_id: &Uuid, permission_level: &ActionPermissionLevel) -> Result<AccessPolicy, TestSlashstepServerError> {

  let access_policy = AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: action_id.clone(),
    permission_level: permission_level.clone(),
    is_inheritance_enabled: true,
    principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
    principal_user_id: Some(user_id.clone()),
    scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::AppCredential,
    scoped_app_credential_id: Some(scoped_app_credential_id.clone()),
    ..Default::default()
  }, database_pool).await?;

  return Ok(access_policy);

}

#[tokio::test]
async fn verify_successful_access_policy_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "slashstep.accessPolicies.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_access_policies_action = Action::get_by_name("slashstep.accessPolicies.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_access_policies_action.id, &ActionPermissionLevel::User).await?;
  
  // Give the user editor access to a dummy action.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;
  let dummy_action = test_environment.create_random_action(None).await?;
  test_environment.create_server_access_policy(&user.id, &dummy_action.id, &ActionPermissionLevel::Editor).await?;

  // Set up the server and send the request.
  let initial_access_policy_properties = InitialAccessPolicyPropertiesForPredefinedScope {
    action_id: dummy_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/app-credentials/{}/access-policies", dummy_app_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_access_policy_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_access_policy: AccessPolicy = response.json();
  assert_eq!(initial_access_policy_properties.action_id, response_access_policy.action_id);
  assert_eq!(initial_access_policy_properties.principal_type, response_access_policy.principal_type);
  assert_eq!(initial_access_policy_properties.principal_user_id, response_access_policy.principal_user_id);
  assert_eq!(initial_access_policy_properties.permission_level, response_access_policy.permission_level);
  assert_eq!(initial_access_policy_properties.is_inheritance_enabled, response_access_policy.is_inheritance_enabled);

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_access_policy_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.accessPolicies.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.accessPolicies.list" action.
  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;
  let shown_access_policy = create_app_credential_access_policy(&test_environment.database_pool, &dummy_app_credential.id, &user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_access_policies: ListResourcesResponseBody::<AccessPolicy> = response.json();
  assert_eq!(response_access_policies.total_count, 1);
  assert_eq!(response_access_policies.resources.len(), 1);

  let query = format!("scoped_resource_type = 'AppCredential' AND scoped_app_credential_id = {}", quote_literal(&dummy_app_credential.id.to_string()));
  let actual_access_policy_count = AccessPolicy::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.total_count, actual_access_policy_count);

  let actual_access_policies = AccessPolicy::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.resources.len(), actual_access_policies.len());
  assert_eq!(response_access_policies.resources[0].id, actual_access_policies[0].id);
  assert_eq!(response_access_policies.resources[0].id, shown_access_policy.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_access_policy_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.accessPolicies.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.accessPolicies.list" action.
  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;
  create_app_credential_access_policy(&test_environment.database_pool, &dummy_app_credential.id, &user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

  let shown_access_policy = create_app_credential_access_policy(&test_environment.database_pool, &dummy_app_credential.id, &user.id, &get_access_policies_action.id, &ActionPermissionLevel::Editor).await?;

  // Set up the server and send the request.
  let additional_query = format!("permission_level = 'Editor'");
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_access_policies: ListResourcesResponseBody::<AccessPolicy> = response.json();
  assert_eq!(response_access_policies.total_count, 1);
  assert_eq!(response_access_policies.resources.len(), 1);

  let query = format!("scoped_resource_type = 'AppCredential' AND scoped_app_credential_id = {} and permission_level = 'Editor'", quote_literal(&dummy_app_credential.id.to_string()));
  let actual_access_policy_count = AccessPolicy::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.total_count, actual_access_policy_count);

  let actual_access_policies = AccessPolicy::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.resources.len(), actual_access_policies.len());
  assert_eq!(response_access_policies.resources[0].id, actual_access_policies[0].id);
  assert_eq!(response_access_policies.resources[0].id, shown_access_policy.id);

  return Ok(());

}

/// Verifies that the default access policy list limit is enforced.
#[tokio::test]
async fn verify_default_access_policy_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "slashstep.accessPolicies.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "slashstep.accessPolicies.list" action.
  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;
  for _ in 0..(DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1) {

    let random_action = test_environment.create_random_action(None).await?;
    let random_user = test_environment.create_random_user().await?;
    create_app_credential_access_policy(&test_environment.database_pool, &dummy_app_credential.id, &random_user.id, &random_action.id, &ActionPermissionLevel::User).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<AccessPolicy> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_ACCESS_POLICY_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_access_policy_list_limit() -> Result<(), TestSlashstepServerError> {

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
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_access_policies_action.id, &ActionPermissionLevel::User).await?;
  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

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
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

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
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_access_policies_action.id, &ActionPermissionLevel::User).await?;

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_access_policies_action.id, &ActionPermissionLevel::User).await?;

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

  let bad_requests = vec![
    test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
      .add_query_param("query", format!("SELECT * FROM access_policies")),
    test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
      .add_query_param("query", format!("SELECT * FROM access_policies WHERE action_id = {}", get_access_policies_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
      .add_query_param("query", format!("action_ied = {}", get_access_policies_action.id)),
    test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
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
async fn verify_authentication_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

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
  let dummy_app_credential = test_environment.create_random_app_credential(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/app-credentials/{}/access-policies", &dummy_app_credential.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}