use std::net::SocketAddr;

use axum::{Extension, middleware};
use axum_test::TestServer;
use anyhow::Result;
use ntest::timeout;
use crate::{AppState, RequestData, initialize_required_tables, middleware::http_request_middleware, tests::TestEnvironment};

/// Verifies that the router can return a 200 status code and the requested access policy.
#[tokio::test]
#[timeout(15000)]
async fn get_access_policy_by_id() -> Result<()> {
  
  return Ok(());
  
}

/// Verifies that the router can return a 400 if the access policy ID is not a UUID.
#[test]
fn verify_uuid_when_getting_access_policy_by_id() {

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[test]
fn verify_authentication_when_getting_access_policy_by_id() {

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the access policy.
#[test]
fn verify_permission_when_getting_access_policy_by_id() {

}

/// Verifies that the router can return a 404 status code if the requested access policy doesn't exist
#[tokio::test]
#[timeout(10000)]
async fn verify_not_found_when_getting_access_policy_by_id() -> Result<()> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&mut test_environment.postgres_pool.get().await?).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool,
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get("/access-policies/00000000-0000-0000-0000-000000000000").await;
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