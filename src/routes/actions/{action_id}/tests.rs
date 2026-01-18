use std::net::SocketAddr;
use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use uuid::Uuid;
use crate::{
  Action, 
  AppState, 
  SlashstepServerError, 
  initialize_required_tables, 
  middleware::http_request_middleware, 
  pre_definitions::{
    initialize_pre_defined_actions, 
    initialize_pre_defined_roles
  }, 
  resources::{
    access_policy::{
      AccessPolicy, 
      AccessPolicyError,
      AccessPolicyPermissionLevel, 
      AccessPolicyPrincipalType, 
      AccessPolicyResourceType, 
      InitialAccessPolicyProperties
    }, 
    session::Session
  }, 
  tests::TestEnvironment
};

/// Verifies that the router can return a 200 status code and the requested action.
#[tokio::test]
#[timeout(20000)]
async fn verify_returned_action_by_id() -> Result<(), SlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
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
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  };
  AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;
  
  let action = test_environment.create_random_action().await?;

  let response = test_server.get(&format!("/actions/{}", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_action: Action = response.json();
  assert_eq!(response_action.id, action.id);
  assert_eq!(response_action.app_id, action.app_id);
  assert_eq!(response_action.name, action.name);
  assert_eq!(response_action.display_name, action.display_name);
  assert_eq!(response_action.description, action.description);

  return Ok(());
  
}

/// Verifies that the router can return a 400 if the action ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.get("/actions/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  
  let action = test_environment.create_random_action().await?;

  let response = test_server.get(&format!("/actions/{}", action.id))
    .await;
  
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the action.
#[tokio::test]
#[timeout(20000)]
async fn verify_permission_when_getting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;

  // Create the user, the session, and the action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let action = test_environment.create_random_action().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/actions/{}", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested action doesn't exist
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_getting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&mut test_environment.postgres_pool.get().await?).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/actions/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 204 status code if the action is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Grant access to the "slashstep.actions.delete" action to the user.
  let delete_actions_action = Action::get_by_name("slashstep.actions.delete", &mut postgres_client).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: delete_actions_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await?;

  // Set up the server and send the request.
  let action = test_environment.create_random_action().await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/actions/{}", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 204);

  match AccessPolicy::get_by_id(&action.id, &mut postgres_client).await.expect_err("Expected an action not found error.") {

    AccessPolicyError::NotFoundError(_) => {},

    error => return Err(SlashstepServerError::AccessPolicyError(error))

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the action ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };

  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.delete("/actions/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Create a dummy action.
  let action = test_environment.create_random_action().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/actions/{}", action.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the action.
#[tokio::test]
async fn verify_permission_when_deleting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create a dummy action.
  let action = test_environment.create_random_action().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/actions/{}", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the action does not exist.
#[tokio::test]
async fn verify_action_exists_when_deleting_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&mut test_environment.postgres_pool.get().await?).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.delete(&format!("/actions/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 200 status code if the action is successfully patched.
#[tokio::test]
async fn verify_successful_patch_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.update", &mut postgres_client).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: get_actions_action.id,
    permission_level: AccessPolicyPermissionLevel::Editor,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await?;

  // Set up the server and send the request.
  let original_action = test_environment.create_random_action().await?;
  let new_name = format!("slashstep.{}.{}", Uuid::now_v7().to_string(), Uuid::now_v7().to_string());
  let new_display_name = Uuid::now_v7().to_string();
  let new_description = Uuid::now_v7().to_string();

  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/actions/{}", original_action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "name": new_name,
      "display_name": new_display_name,
      "description": new_description
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let updated_action: Action = response.json();
  assert_eq!(original_action.id, updated_action.id);
  assert_eq!(new_name, updated_action.name);
  assert_eq!(new_display_name, updated_action.display_name);
  assert_eq!(new_description, updated_action.description);
  assert_eq!(original_action.app_id, updated_action.app_id);
  assert_eq!(original_action.parent_resource_type, updated_action.parent_resource_type);

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
#[tokio::test]
async fn verify_content_type_when_patching_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/actions/not-a-uuid")
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_exists_when_patching_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/actions/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body includes unwanted data.
#[tokio::test]
async fn verify_request_body_json_when_patching_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/actions/{}", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "name": "Super Duper Admin",
      "display_name": "true",
      "description": true,
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the action ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_patching_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/actions/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_patching_action_by_id() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Set up the server and send the request.
  let action = test_environment.create_random_action().await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/actions/{}", action.id))
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  assert_eq!(response.status_code(), 401);

  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to patch the action.
#[tokio::test]
async fn verify_permission_when_patching_action() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let action = test_environment.create_random_action().await?;
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/actions/{}", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 403);

  return Ok(());

}

/// Verifies that the router can return a 404 status code if the action does not exist.
#[tokio::test]
async fn verify_action_exists_when_patching_action() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/actions/{}", Uuid::now_v7()))
    .json(&serde_json::json!({
      "display_name": Uuid::now_v7().to_string()
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 404);

  return Ok(());

}