/**
 * 
 * Any test cases for /projects/{project_id} should be handled here.
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
use chrono::DateTime;
use ntest::timeout;
use reqwest::StatusCode;
use crate::{
  Action, AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, resources::{
    access_policy::
      ActionPermissionLevel
    , project::{Project},
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_projects_action = Action::get_by_name("slashstep.projects.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_projects_action.id, &ActionPermissionLevel::User).await?;
  
  let project = test_environment.create_random_project().await?;

  let response = test_server.get(&format!("/projects/{}", project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_project: Project = response.json();
  assert_eq!(response_project.id, project.id);
  assert_eq!(response_project.name, project.name);
  assert_eq!(response_project.display_name, project.display_name);
  assert_eq!(response_project.key, project.key);
  assert_eq!(response_project.description, project.description);
  assert_eq!(response_project.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), project.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(response_project.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), project.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the app ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {

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

  let response = test_server.get("/projects/not-a-uuid")
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let project = test_environment.create_random_project().await?;

  let response = test_server.get(&format!("/projects/{}", project.id))
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

  // Create the user, the session, and the action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/projects/{}", project.id))
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
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/projects/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
  return Ok(());

}

// /// Verifies that the router can return a 204 status code if the action is successfully deleted.
// #[tokio::test]
// async fn verify_successful_deletion_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

//   // Grant access to the "slashstep.projects.delete" action to the user.
//   let delete_fields_action = Action::get_by_name("slashstep.projects.delete", &test_environment.database_pool).await?;
//   AccessPolicy::create(&InitialAccessPolicyProperties {
//     action_id: delete_fields_action.id,
//     permission_level: ActionPermissionLevel::User,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: AccessPolicyResourceType::Server,
//     ..Default::default()
//   }, &test_environment.database_pool).await?;

//   // Set up the server and send the request.
//   let project = test_environment.create_random_project().await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/projects/{}", project.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   assert_eq!(response.status_code(), 204);

//   match App::get_by_id(&project.id, &test_environment.database_pool).await.expect_err("Expected an app not found error.") {

//     ResourceError::NotFoundError(_) => {},

//     error => return Err(TestSlashstepServerError::ResourceError(error))

//   }

//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the ID is not a UUID.
// #[tokio::test]
// async fn verify_uuid_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;

//   let response = test_server.delete("/projects/not-a-uuid")
//     .await;
  
//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 401 status code if the user needs authentication.
// #[tokio::test]
// async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Create a dummy app.
//   let project = test_environment.create_random_project().await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/projects/{}", project.id))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
//   return Ok(());

// }

// /// Verifies that the router can return a 403 status code if the user does not have permission to delete the resource.
// #[tokio::test]
// async fn verify_permission_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
//   // Create a dummy app.
//   let project = test_environment.create_random_project().await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/projects/{}", project.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
//   return Ok(());

// }

// /// Verifies that the router can return a 404 status code if the resource does not exist.
// #[tokio::test]
// async fn verify_resource_exists_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/projects/{}", uuid::Uuid::now_v7()))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), 404);
//   return Ok(());

// }

// /// Verifies that the router can return a 200 status code if the resource is successfully patched.
// #[tokio::test]
// async fn verify_successful_patch_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
//   let update_fields_action = Action::get_by_name("slashstep.projects.update", &test_environment.database_pool).await?;
//   AccessPolicy::create(&InitialAccessPolicyProperties {
//     action_id: update_fields_action.id,
//     permission_level: ActionPermissionLevel::Editor,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: AccessPolicyResourceType::Server,
//     ..Default::default()
//   }, &test_environment.database_pool).await?;

//   // Set up the server and send the request.
//   let original_app = test_environment.create_random_app().await?;
//   let new_name = Uuid::now_v7().to_string();
//   let new_display_name = Uuid::now_v7().to_string();
//   let new_description = Some(Uuid::now_v7().to_string());
//   let new_client_type = AppClientType::Confidential;

//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch(&format!("/projects/{}", original_field.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .json(&serde_json::json!({
//       "name": new_name.clone(),
//       "display_name": new_display_name.clone(),
//       "description": new_description.clone(),
//       "client_type": new_client_type.clone()
//     }))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), 200);

//   let updated_app: Field = response.json();
//   assert_eq!(original_field.id, updated_field.id);
//   assert_eq!(updated_app.name, new_name);
//   assert_eq!(updated_app.display_name, new_display_name);
//   assert_eq!(updated_app.description, new_description);
//   assert_eq!(updated_app.client_type, new_client_type);
//   assert_eq!(original_app.parent_resource_type, updated_app.parent_resource_type);
//   assert_eq!(original_app.parent_workspace_id, updated_app.parent_workspace_id);
//   assert_eq!(original_app.parent_user_id, updated_app.parent_user_id);

//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
// #[tokio::test]
// async fn verify_content_type_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch("/projects/not-a-uuid")
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request body is not valid JSON.
// #[tokio::test]
// async fn verify_request_body_exists_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch("/projects/not-a-uuid")
//     .add_header("Content-Type", "application/json")
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request body includes unwanted data.
// #[tokio::test]
// async fn verify_request_body_json_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch(&format!("/projects/{}", uuid::Uuid::now_v7()))
//     .add_header("Content-Type", "application/json")
//     .json(&serde_json::json!({
//       "name": "Super Duper Admin",
//       "display_name": "true",
//       "description": true,
//     }))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the resource ID is not a UUID.
// #[tokio::test]
// async fn verify_uuid_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch("/projects/not-a-uuid")
//     .add_header("Content-Type", "application/json")
//     .json(&serde_json::json!({
//       "display_name": Uuid::now_v7().to_string()
//     }))
//     .await;
  
//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 401 status code if the user needs authentication.
// #[tokio::test]
// async fn verify_authentication_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
  
//   // Set up the server and send the request.
//   let project = test_environment.create_random_project().await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch(&format!("/projects/{}", project.id))
//     .json(&serde_json::json!({
//       "display_name": Uuid::now_v7().to_string()
//     }))
//     .await;
  
//   assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

//   return Ok(());

// }

// /// Verifies that the router can return a 403 status code if the user does not have permission to patch the resource.
// #[tokio::test]
// async fn verify_permission_when_patching() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;

//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

//   // Set up the server and send the request.
//   let project = test_environment.create_random_project().await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch(&format!("/projects/{}", project.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .json(&serde_json::json!({
//       "display_name": Uuid::now_v7().to_string()
//     }))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

//   return Ok(());

// }

// /// Verifies that the router can return a 404 status code if the resource does not exist.
// #[tokio::test]
// async fn verify_resource_exists_when_patching() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.patch(&format!("/projects/{}", Uuid::now_v7()))
//     .json(&serde_json::json!({
//       "display_name": Uuid::now_v7().to_string()
//     }))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), 404);

//   return Ok(());

// }