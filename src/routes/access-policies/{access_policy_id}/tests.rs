use std::net::SocketAddr;
use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use crate::{Action, AppState, SlashstepServerError, initialize_required_tables, middleware::http_request_middleware, pre_definitions::{initialize_pre_defined_actions, initialize_pre_defined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyInheritanceLevel, AccessPolicyPermissionLevel, AccessPolicyPrincipalType, AccessPolicyScopedResourceType, InitialAccessPolicyProperties}, session::Session}, tests::TestEnvironment};

/// Verifies that the router can return a 200 status code and the requested access policy.
#[tokio::test]
#[timeout(15000)]
async fn verify_returned_access_policy_by_id() -> Result<(), SlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  let _ = initialize_pre_defined_actions(&mut postgres_client).await?;
  let _ = initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    inheritance_level: AccessPolicyInheritanceLevel::Enabled,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyScopedResourceType::Instance,
    ..Default::default()
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

  let response = test_server.get(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_access_policy: AccessPolicy = response.json();
  assert_eq!(response_access_policy.id, access_policy.id);
  assert_eq!(response_access_policy.action_id, access_policy.action_id);
  assert_eq!(response_access_policy.permission_level, access_policy.permission_level);
  assert_eq!(response_access_policy.inheritance_level, access_policy.inheritance_level);
  assert_eq!(response_access_policy.principal_type, access_policy.principal_type);
  assert_eq!(response_access_policy.principal_user_id, access_policy.principal_user_id);
  assert_eq!(response_access_policy.principal_group_id, access_policy.principal_group_id);
  assert_eq!(response_access_policy.principal_role_id, access_policy.principal_role_id);
  assert_eq!(response_access_policy.principal_app_id, access_policy.principal_app_id);
  assert_eq!(response_access_policy.scoped_resource_type, access_policy.scoped_resource_type);
  assert_eq!(response_access_policy.scoped_action_id, access_policy.scoped_action_id);
  assert_eq!(response_access_policy.scoped_app_id, access_policy.scoped_app_id);
  assert_eq!(response_access_policy.scoped_group_id, access_policy.scoped_group_id);
  assert_eq!(response_access_policy.scoped_item_id, access_policy.scoped_item_id);
  assert_eq!(response_access_policy.scoped_milestone_id, access_policy.scoped_milestone_id);
  assert_eq!(response_access_policy.scoped_project_id, access_policy.scoped_project_id);
  assert_eq!(response_access_policy.scoped_role_id, access_policy.scoped_role_id);
  assert_eq!(response_access_policy.scoped_user_id, access_policy.scoped_user_id);
  assert_eq!(response_access_policy.scoped_workspace_id, access_policy.scoped_workspace_id);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the access policy ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_access_policy_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  let _ = initialize_pre_defined_actions(&mut postgres_client).await?;
  let _ = initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get("/access-policies/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_access_policy_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  let _ = initialize_pre_defined_actions(&mut postgres_client).await?;
  let _ = initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.get(&format!("/access-policies/{}", access_policy.id))
    .await;
  
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the access policy.
#[tokio::test]
#[timeout(15000)]
async fn verify_permission_when_getting_access_policy_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  let _ = initialize_pre_defined_actions(&mut postgres_client).await?;
  let _ = initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.get(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested access policy doesn't exist
#[tokio::test]
#[timeout(15000)]
async fn verify_not_found_when_getting_access_policy_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&mut test_environment.postgres_pool.get().await?).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  let response = test_server.get(&format!("/access-policies/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 204 status code if the access policy is successfully deleted.
#[test]
fn verify_successful_deletion_when_deleting_access_policy_by_id() {

}

/// Verifies that the router can return a 400 status code if the access policy ID is not a UUID.
#[test]
fn verify_uuid_when_deleting_access_policy_by_id() {

}

#[test]
fn verify_authentication_when_deleting_access_policy_by_id() {

}

#[test]
fn verify_permission_when_deleting_access_policy_by_id() {

}

#[test]
fn verify_access_policy_exists_when_deleting_access_policy_by_id() {

}

#[test]
fn patch_access_policy() {

}

#[test]
fn verify_uuid_when_patching_access_policy() {

}

#[test]
fn verify_authentication_when_patching_access_policy() {

}

#[test]
fn verify_permission_when_patching_access_policy() {

}

#[test]
fn verify_access_policy_exists_when_patching_access_policy() {

}