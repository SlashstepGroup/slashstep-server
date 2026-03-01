/**
 * 
 * Any test cases for /groups/{app_id}/memberships should be handled here.
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
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{ActionPermissionLevel, IndividualPrincipal}, action::Action, membership::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, InitialMembershipProperties, InitialMembershipPropertiesWithPredefinedParent, Membership, MembershipParentResourceType, MembershipPrincipalType}}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "memberships.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_memberships_action = Action::get_by_name("memberships.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "memberships.list" action.
  let list_memberships_action = Action::get_by_name("memberships.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;
  let dummy_membership = Membership::create(&InitialMembershipProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(dummy_group.id),
    principal_type: MembershipPrincipalType::User,
    principal_user_id: Some(user.id),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Membership> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("parent_group_id = {}", quote_literal(&dummy_group.id.to_string()));
  let actual_membership_count = Membership::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_membership_count);

  let actual_memberships = Membership::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_memberships.len());
  assert_eq!(response_body.resources[0].id, actual_memberships[0].id);
  assert_eq!(response_body.resources[0].id, dummy_membership.id);

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
  
  // Give the user access to the "memberships.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_memberships_action = Action::get_by_name("memberships.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "memberships.list" action.
  let list_memberships_action = Action::get_by_name("memberships.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;
  let dummy_membership = Membership::create(&InitialMembershipProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(dummy_group.id),
    principal_type: MembershipPrincipalType::User,
    principal_user_id: Some(user.id),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = {}", quote_literal(&dummy_membership.id.to_string()));
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_membership.parent_group_id.unwrap()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Membership> = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.resources.len(), 1);

  let query = format!("parent_group_id = {} AND {}", quote_literal(&dummy_group.id.to_string()), &additional_query);
  let actual_membership_count = Membership::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_membership_count);

  let actual_memberships = Membership::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.resources.len(), actual_memberships.len());
  assert_eq!(response_body.resources[0].id, actual_memberships[0].id);
  assert_eq!(response_body.resources[0].id, dummy_membership.id);

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
  
  // Grant access to the "memberships.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_memberships_action = Action::get_by_name("memberships.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "memberships.list" action to the user.
  let list_memberships_action = Action::get_by_name("memberships.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;
  let membership_count = Membership::count(format!("parent_group_id = {}", quote_literal(&dummy_group.id.to_string())).as_str(), &test_environment.database_pool, None).await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - membership_count + 1) {

    Membership::create(&InitialMembershipProperties {
      parent_resource_type: MembershipParentResourceType::Group,
      parent_group_id: Some(dummy_group.id),
      principal_type: MembershipPrincipalType::User,
      principal_user_id: Some(test_environment.create_random_user().await?.id),
      ..Default::default()
    }, &test_environment.database_pool).await?;

  }

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<Membership> = response.json();
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
  
  // Grant access to the "memberships.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_memberships_action = Action::get_by_name("memberships.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "memberships.list" action to the user.
  let list_memberships_action = Action::get_by_name("memberships.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
    .add_query_param("query", format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1))
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Grant access to the "memberships.get" action to the user.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_memberships_action = Action::get_by_name("memberships.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Grant access to the "memberships.list" action to the user.
  let list_memberships_action = Action::get_by_name("memberships.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
      .add_query_param("query", format!("SELECT * FROM memberships")),
    test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
      .add_query_param("query", format!("SELECT * FROM memberships WHERE id = {}", get_memberships_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
      .add_query_param("query", format!("app_ied = {}", get_memberships_action.id)),
    test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a user and a session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &dummy_group.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1))
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/memberships", &Uuid::now_v7()))
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
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "apps.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_memberships_action = Action::get_by_name("memberships.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_memberships_action.id, &ActionPermissionLevel::User).await?;

  // Create a dummy resource.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let initial_membership_properties = InitialMembershipPropertiesWithPredefinedParent {
    principal_type: MembershipPrincipalType::User,
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
  let response = test_server.post(&format!("/groups/{}/memberships", dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_membership_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_membership: Membership = response.json();
  assert_eq!(response_membership.parent_resource_type, MembershipParentResourceType::Group);
  assert_eq!(response_membership.parent_group_id, Some(dummy_group.id));
  assert_eq!(response_membership.parent_role_id, None);
  assert_eq!(response_membership.principal_type, MembershipPrincipalType::User);
  assert_eq!(response_membership.principal_user_id, Some(user.id));
  assert_eq!(response_membership.principal_app_id, None);
  assert_eq!(response_membership.principal_group_id, None);

  return Ok(());
  
}

/// Verifies that the server returns a 400 status code when the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_json_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create a dummy group.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/groups/{}/memberships", dummy_group.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "principal_type": true
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create a dummy resource.
  let user = test_environment.create_random_user().await?;
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let initial_membership_properties = InitialMembershipPropertiesWithPredefinedParent {
    principal_type: MembershipPrincipalType::User,
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
  let response = test_server.post(&format!("/groups/{}/memberships", dummy_group.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_membership_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_creating_resource() -> Result<(), TestSlashstepServerError> {

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
  
  // Create a dummy resource.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let initial_membership_properties = InitialMembershipPropertiesWithPredefinedParent {
    principal_type: MembershipPrincipalType::User,
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
  let response = test_server.post(&format!("/groups/{}/memberships", dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_membership_properties))
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
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let user = test_environment.create_random_user().await?;
  let initial_membership_properties = InitialMembershipPropertiesWithPredefinedParent {
    principal_type: MembershipPrincipalType::User,
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

  let response = test_server.post(&format!("/groups/{}/memberships", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_membership_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
  return Ok(());

}