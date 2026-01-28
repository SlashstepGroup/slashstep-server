
use std::net::SocketAddr;
use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use uuid::Uuid;
use crate::{
  Action, 
  AppState,
  initialize_required_tables, 
  middleware::http_request_middleware, 
  predefinitions::{
    initialize_pre_defined_actions, 
    initialize_pre_defined_roles
  }, 
  resources::{
    ResourceError, access_policy::{
      AccessPolicy,
      AccessPolicyPermissionLevel, 
      AccessPolicyPrincipalType, 
      AccessPolicyResourceType, 
      InitialAccessPolicyProperties
    }, session::Session
  }, 
  tests::{TestEnvironment, TestSlashstepServerError}
};

/// Verifies that the router can return a 200 status code and the requested access policy.
#[tokio::test]
#[timeout(20000)]
async fn verify_returned_access_policy_by_id() -> Result<(), TestSlashstepServerError> {
  
  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
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
  assert_eq!(response_access_policy.is_inheritance_enabled, access_policy.is_inheritance_enabled);
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
async fn verify_uuid_when_getting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.get("/access-policies/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.get(&format!("/access-policies/{}", access_policy.id))
    .await;
  
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the access policy.
#[tokio::test]
#[timeout(20000)]
async fn verify_permission_when_getting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.get(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the requested access policy doesn't exist
#[tokio::test]
#[timeout(20000)]
async fn verify_not_found_when_getting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

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
#[tokio::test]
async fn verify_successful_deletion_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let delete_access_policies_action = Action::get_by_name("slashstep.accessPolicies.delete", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: delete_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::Editor,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

  let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 204);

  match AccessPolicy::get_by_id(&access_policy.id, &mut postgres_client).await.expect_err("Expected an access policy not found error.") {

    ResourceError::NotFoundError(_) => {},

    error => return Err(TestSlashstepServerError::ResourceError(error))

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the access policy ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.delete("/access-policies/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
    .await;
  
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the access policy.
#[tokio::test]
async fn verify_permission_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let access_policy = test_environment.create_random_access_policy().await?;

  let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 403);
  return Ok(());

}

/// Verifies that the router can return a 404 status code if the access policy does not exist.
#[tokio::test]
async fn verify_access_policy_exists_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

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

  let response = test_server.delete(&format!("/access-policies/{}", uuid::Uuid::now_v7()))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 200 status code if the access policy is successfully patched.
#[tokio::test]
async fn verify_successful_patch_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.update", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::Editor,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

  let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "permission_level": "User",
      "is_inheritance_enabled": false
    }))
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_access_policy: AccessPolicy = response.json();
  assert_eq!(response_access_policy.id, access_policy.id);
  assert_eq!(response_access_policy.action_id, access_policy.action_id);
  assert_eq!(response_access_policy.permission_level, AccessPolicyPermissionLevel::User);
  assert_eq!(response_access_policy.is_inheritance_enabled, false);
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

/// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
#[tokio::test]
async fn verify_content_type_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.patch("/access-policies/not-a-uuid")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_exists_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.patch("/access-policies/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request body includes unwanted data.
#[tokio::test]
async fn verify_request_body_json_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.patch("/access-policies/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "permission_level": "Super Duper Admin",
      "is_inheritance_enabled": "true",
      "principal_type": "User2",
    }))
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 400 status code if the access policy ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.patch("/access-policies/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "permission_level": "Editor",
      "is_inheritance_enabled": false
    }))
    .await;
  
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.update", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: get_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::Editor,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

  let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
    .json(&serde_json::json!({
      "permission_level": "User",
      "is_inheritance_enabled": false
    }))
    .await;
  
  assert_eq!(response.status_code(), 401);

  return Ok(());

}

/// Verifies that the router can return a 403 status code if the user does not have permission to patch the access policy.
#[tokio::test]
async fn verify_permission_when_patching_access_policy() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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
  let update_access_policies_action = Action::get_by_name("slashstep.accessPolicies.update", &mut postgres_client).await?;
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: update_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::None,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

  let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "permission_level": "User",
      "is_inheritance_enabled": false
    }))
    .await;
  
  assert_eq!(response.status_code(), 403);

  return Ok(());

}

/// Verifies that the router can return a 404 status code if the access policy does not exist.
#[tokio::test]
async fn verify_access_policy_exists_when_patching_access_policy() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
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

  let response = test_server.patch(&format!("/access-policies/{}", Uuid::now_v7()))
    .json(&serde_json::json!({
      "permission_level": "User",
      "is_inheritance_enabled": false
    }))
    .await;
  
  assert_eq!(response.status_code(), 404);

  return Ok(());

}