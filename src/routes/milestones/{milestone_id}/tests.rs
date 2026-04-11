/**
 * 
 * Any test cases for /milestones/{milestone_id} should be handled here.
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
use reqwest::StatusCode;
use rust_decimal::Decimal;
use uuid::Uuid;
use crate::{
  Action, AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, initialize_predefined_configurations, 
    initialize_predefined_roles
  }, resources::{
    ResourceError, access_policy::ActionPermissionLevel, configuration::{Configuration, EditableConfigurationProperties}, milestone::{EditableMilestoneProperties, Milestone}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(20000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_milestones_action = Action::get_by_name("milestones.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_milestones_action.id, &ActionPermissionLevel::User).await?;
  
  let milestone = test_environment.create_random_milestone(None).await?;

  let response = test_server.get(&format!("/milestones/{}", milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_milestone: Milestone = response.json();
  assert_eq!(response_milestone.id, milestone.id);
  assert_eq!(response_milestone.display_name, milestone.display_name);
  assert_eq!(response_milestone.description, milestone.description);
  assert_eq!(response_milestone.start_date, milestone.start_date);
  assert_eq!(response_milestone.end_date, milestone.end_date);
  assert_eq!(response_milestone.parent_resource_type, milestone.parent_resource_type);
  assert_eq!(response_milestone.parent_project_id, milestone.parent_project_id);
  assert_eq!(response_milestone.parent_workspace_id, milestone.parent_workspace_id);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the app ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let response = test_server.get("/milestones/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the requestor needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  
  let milestone = test_environment.create_random_milestone(None).await?;

  let response = test_server.get(&format!("/milestones/{}", milestone.id))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the requestor does not have permission to get the app.
#[tokio::test]
#[timeout(20000)]
async fn verify_permission_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create the user, the session, and the action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let milestone = test_environment.create_random_milestone(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/milestones/{}", milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested resource doesn't exist
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

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

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/milestones/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
  return Ok(());

}

/// Verifies that the router can return a 204 status code if the action is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

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

  // Grant access to the "milestones.delete" action to the user.
  let delete_milestones_action = Action::get_by_name("milestones.delete", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &delete_milestones_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let milestone = test_environment.create_random_milestone(None).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.delete(&format!("/milestones/{}", milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

  match Milestone::get_by_id(&milestone.id, &test_environment.database_pool).await.expect_err("Expected an milestone not found error.") {

    ResourceError::NotFoundError(_) => {},

    error => return Err(TestSlashstepServerError::ResourceError(error))

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let response = test_server.delete("/milestones/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create a dummy app.
  let milestone = test_environment.create_random_milestone(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.delete(&format!("/milestones/{}", milestone.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the resource.
#[tokio::test]
async fn verify_permission_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

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
  
  // Create a dummy app.
  let milestone = test_environment.create_random_milestone(None).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.delete(&format!("/milestones/{}", milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the resource does not exist.
#[tokio::test]
async fn verify_resource_exists_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

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

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.delete(&format!("/milestones/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
  return Ok(());

}

/// Verifies that the router can return a 200 status code if the resource is successfully patched.
#[tokio::test]
async fn verify_successful_patch_by_id() -> Result<(), TestSlashstepServerError> {

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
  let update_milestones_action = Action::get_by_name("milestones.update", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &update_milestones_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let original_milestone = test_environment.create_random_milestone(None).await?;
  let updated_milestone_properties = EditableMilestoneProperties {
    name: Some(Uuid::now_v7().to_string()),
    display_name: Some(Uuid::now_v7().to_string()),
    description: Some(Some(Uuid::now_v7().to_string())),
    start_date: Some(Some(chrono::Utc::now())),
    end_date: Some(Some(chrono::Utc::now() + chrono::Duration::days(7))),
    ..Default::default()
   };

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", original_milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(updated_milestone_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let updated_milestone: Milestone = response.json();
  assert_eq!(original_milestone.id, updated_milestone.id);
  assert_eq!(updated_milestone.display_name, updated_milestone_properties.display_name.unwrap());
  assert_eq!(updated_milestone.name, updated_milestone_properties.name.unwrap());
  assert_eq!(updated_milestone.description, updated_milestone_properties.description.unwrap());
  assert_eq!(updated_milestone.start_date.map(|date| date.timestamp_millis()), Some(updated_milestone_properties.start_date.unwrap().unwrap().timestamp_millis()));
  assert_eq!(updated_milestone.end_date.map(|date| date.timestamp_millis()), Some(updated_milestone_properties.end_date.unwrap().unwrap().timestamp_millis()));

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
#[tokio::test]
async fn verify_content_type_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

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
  let test_server = TestServer::new(router);
  let response = test_server.patch("/milestones/not-a-uuid")
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_exists_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

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
  let test_server = TestServer::new(router);
  let response = test_server.patch("/milestones/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body includes unwanted data.
#[tokio::test]
async fn verify_request_body_json_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

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
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "display_name": true
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the resource ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch("/milestones/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .await;
  
  assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Set up the server and send the request.
  let milestone = test_environment.create_random_milestone(None).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", milestone.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to patch the resource.
#[tokio::test]
async fn verify_permission_when_patching() -> Result<(), TestSlashstepServerError> {

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

  // Set up the server and send the request.
  let milestone = test_environment.create_random_milestone(None).await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}

/// Verifies that the router can return a 404 status code if the resource does not exist.
#[tokio::test]
async fn verify_resource_exists_when_patching() -> Result<(), TestSlashstepServerError> {

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
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", Uuid::now_v7()))
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the milestone display name is over the maximum length.
#[tokio::test]
async fn verify_milestone_display_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

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
  let update_milestone_action = Action::get_by_name("milestones.update", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &update_milestone_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let original_milestone = test_environment.create_random_milestone(None).await?; 
  let maximum_milestone_display_name_length_configuration = Configuration::get_by_name("milestones.maximumDisplayNameLength", &test_environment.database_pool).await?;
  maximum_milestone_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let updated_milestone_properties = EditableMilestoneProperties {
    display_name: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", original_milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(updated_milestone_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when milestone descriptions are over the maximum length.
#[tokio::test]
async fn verify_milestone_description_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {

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
  let update_milestone_action = Action::get_by_name("milestones.update", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &update_milestone_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let original_milestone = test_environment.create_random_milestone(None).await?; 
  let maximum_milestone_display_name_length_configuration = Configuration::get_by_name("milestones.maximumDescriptionLength", &test_environment.database_pool).await?;
  maximum_milestone_display_name_length_configuration.update(&EditableConfigurationProperties {
    number_value: Some(Decimal::from(0 as i64)),
    ..Default::default()
  }, &test_environment.database_pool).await?;

  let updated_milestone_properties = EditableMilestoneProperties {
    description: Some(Some(Uuid::now_v7().to_string())),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.patch(&format!("/milestones/{}", original_milestone.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(updated_milestone_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}