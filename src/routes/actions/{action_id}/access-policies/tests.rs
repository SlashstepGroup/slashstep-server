use std::net::SocketAddr;

use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;

use crate::{AppState, SlashstepServerError, middleware::http_request_middleware, pre_definitions::{initialize_pre_defined_actions, initialize_pre_defined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyPrincipalType, AccessPolicyResourceType, InitialAccessPolicyProperties}, action::Action, session::Session}, routes::actions::action_id::access_policies::InitialAccessPolicyPropertiesForAction, tests::TestEnvironment};

#[tokio::test]
async fn verify_successful_access_policy_creation() -> Result<(), SlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  test_environment.initialize_required_tables().await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  
  // Give the user access to the "slashstep.accessPolicies.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_access_policies_action = Action::get_by_name("slashstep.accessPolicies.create", &mut postgres_client).await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: create_access_policies_action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await?;
  
  // Give the user editor access to a dummy action.
  let action = test_environment.create_random_action().await?;
  AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::Editor,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    scoped_resource_type: AccessPolicyResourceType::Instance,
    ..Default::default()
  }, &mut postgres_client).await?;

  // Set up the server and send the request.
  let initial_access_policy_properties = InitialAccessPolicyPropertiesForAction {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    is_inheritance_enabled: true,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/actions/{}/access-policies", action.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_access_policy_properties))
    .await;
  
  assert_eq!(response.status_code(), 200);

  let response_access_policy: AccessPolicy = response.json();
  assert_eq!(initial_access_policy_properties.action_id, response_access_policy.action_id);
  assert_eq!(initial_access_policy_properties.principal_type, response_access_policy.principal_type);
  assert_eq!(initial_access_policy_properties.principal_user_id, response_access_policy.principal_user_id);
  assert_eq!(initial_access_policy_properties.permission_level, response_access_policy.permission_level);
  assert_eq!(initial_access_policy_properties.is_inheritance_enabled, response_access_policy.is_inheritance_enabled);

  return Ok(());
  
}