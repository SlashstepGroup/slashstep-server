/**
 * 
 * Any test cases for /access-policies should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
 * 
 */

use std::net::SocketAddr;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use reqwest::StatusCode;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPrincipalType, AccessPolicyResourceType, ActionPermissionLevel, DEFAULT_ACCESS_POLICY_LIST_LIMIT, IndividualPrincipal, InitialAccessPolicyProperties}, action::Action}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_access_policy_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  let get_access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&get_access_policy_properties, &test_environment.database_pool).await?;

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  let list_access_policy_properties = InitialAccessPolicyProperties {
    action_id: list_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&list_access_policy_properties, &test_environment.database_pool).await?;

  let response = test_server.get(&format!("/access-policies"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_access_policies: ListResourcesResponseBody::<AccessPolicy> = response.json();
  assert!(response_access_policies.total_count > 0);
  assert!(response_access_policies.resources.len() > 0);

  let actual_access_policy_count = AccessPolicy::count("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.total_count, actual_access_policy_count);

  let actual_access_policies = AccessPolicy::list("", &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.resources.len(), actual_access_policies.len());

  for actual_access_policy in actual_access_policies {

    let found_access_policy = response_access_policies.resources.iter().find(|access_policy| access_policy.id == actual_access_policy.id);
    assert!(found_access_policy.is_some());

  }

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_access_policy_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  let get_access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&get_access_policy_properties, &test_environment.database_pool).await?;

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  let list_access_policy_properties = InitialAccessPolicyProperties {
    action_id: list_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&list_access_policy_properties, &test_environment.database_pool).await?;
  let query = format!("action_id = \'{}\'", get_access_policies_action.id);
  let response = test_server.get(&format!("/access-policies"))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_query_param("query", &query)
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_access_policies: ListResourcesResponseBody::<AccessPolicy> = response.json();
  let actual_access_policy_count = AccessPolicy::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.total_count, actual_access_policy_count);

  let actual_access_policies = AccessPolicy::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_access_policies.resources.len(), actual_access_policies.len());

  for actual_access_policy in actual_access_policies {

    let found_access_policy = response_access_policies.resources.iter().find(|access_policy| access_policy.id == actual_access_policy.id);
    assert!(found_access_policy.is_some());

  }

  return Ok(());

}

/// Verifies that the default access policy list limit is 1000.
#[tokio::test]
async fn verify_default_access_policy_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  let get_access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&get_access_policy_properties, &test_environment.database_pool).await?;

  let access_policy_count = AccessPolicy::count("", &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_ACCESS_POLICY_LIST_LIMIT - access_policy_count + 1) {

    let random_action = test_environment.create_random_action(None).await?;
    let random_user = test_environment.create_random_user().await?;
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: random_action.id,
      permission_level: ActionPermissionLevel::User,
      is_inheritance_enabled: true,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: Some(random_user.id),
      scoped_resource_type: AccessPolicyResourceType::Server,
      ..Default::default()
    };
    AccessPolicy::create(&access_policy_properties, &test_environment.database_pool).await?;

  }

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  let list_access_policy_properties = InitialAccessPolicyProperties {
    action_id: list_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&list_access_policy_properties, &test_environment.database_pool).await?;

  let response = test_server.get(&format!("/access-policies"))
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  let get_access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&get_access_policy_properties, &test_environment.database_pool).await?;

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  let list_access_policy_properties = InitialAccessPolicyProperties {
    action_id: list_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&list_access_policy_properties, &test_environment.database_pool).await?;

  let response = test_server.get(&format!("/access-policies"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &test_environment.database_pool).await?;
  let get_access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&get_access_policy_properties, &test_environment.database_pool).await?;

  let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &test_environment.database_pool).await?;
  let list_access_policy_properties = InitialAccessPolicyProperties {
    action_id: list_access_policies_action.id,
    permission_level: ActionPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Server,
    ..Default::default()
  };
  AccessPolicy::create(&list_access_policy_properties, &test_environment.database_pool).await?;

  let bad_requests = vec![
    test_server.get(&format!("/access-policies"))
      .add_query_param("query", format!("SELECT * FROM access_policies")),
    test_server.get(&format!("/access-policies"))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/access-policies"))
      .add_query_param("query", format!("SELECT * FROM access_policies WHERE action_id = {}", get_access_policies_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/access-policies"))
      .add_query_param("query", format!("action_ied = {}", get_access_policies_action.id)),
    test_server.get(&format!("/access-policies"))
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get(&format!("/access-policies"))
    .await;
  
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  let response = test_server.get(&format!("/access-policies"))
    .add_query_param("query", format!("limit {}", DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}