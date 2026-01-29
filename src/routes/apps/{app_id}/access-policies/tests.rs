use std::net::SocketAddr;
use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, initialize_required_tables, middleware::http_request_middleware, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, AccessPolicyPrincipalType, AccessPolicyResourceType, DEFAULT_ACCESS_POLICY_LIST_LIMIT, IndividualPrincipal, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action::Action, session::Session}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListAccessPolicyResponseBody};

async fn create_instance_access_policy(postgres_client: &mut deadpool_postgres::Client, user_id: &Uuid, action_id: &Uuid, permission_level: &AccessPolicyPermissionLevel) -> Result<AccessPolicy, TestSlashstepServerError> {

  let access_policy = AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: action_id.clone(),
    permission_level: permission_level.clone(),
    is_inheritance_enabled: true,
    principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
    principal_user_id: Some(user_id.clone()),
    scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Instance,
    ..Default::default()
  }, postgres_client).await?;

  return Ok(access_policy);

}

async fn create_action_access_policy(postgres_client: &mut deadpool_postgres::Client, scoped_action_id: &Uuid, user_id: &Uuid, action_id: &Uuid, permission_level: &AccessPolicyPermissionLevel) -> Result<AccessPolicy, TestSlashstepServerError> {

  let access_policy = AccessPolicy::create(&InitialAccessPolicyProperties {
    action_id: action_id.clone(),
    permission_level: permission_level.clone(),
    is_inheritance_enabled: true,
    principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
    principal_user_id: Some(user_id.clone()),
    scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Action,
    scoped_action_id: Some(scoped_action_id.clone()),
    ..Default::default()
  }, postgres_client).await?;

  return Ok(access_policy);

}

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_resource_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;

  // Give the user access to the "slashstep.accessPolicies.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_access_policies_action = Action::get_by_name("slashstep.accessPolicies.create", &mut postgres_client).await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &create_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;
  
  // Give the user editor access to a dummy action.
  let dummy_app = test_environment.create_random_app().await?;
  let dummy_action = test_environment.create_random_action().await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &dummy_action.id, &AccessPolicyPermissionLevel::Editor).await?;

  // Set up the server and send the request.
  let initial_access_policy_properties = InitialAccessPolicyPropertiesForPredefinedScope {
    action_id: dummy_action.id,
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
  let response = test_server.post(&format!("/apps/{}/access-policies", dummy_app.id))
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
  assert_eq!(AccessPolicyResourceType::App, response_access_policy.scoped_resource_type);
  assert_eq!(dummy_app.id, response_access_policy.scoped_app_id.expect("App ID is not set."));

  return Ok(());
  
}