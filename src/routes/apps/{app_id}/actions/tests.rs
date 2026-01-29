use std::net::SocketAddr;

use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::{AppState, initialize_required_tables, middleware::http_request_middleware, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, IndividualPrincipal, InitialAccessPolicyProperties}, action::{Action, ActionParentResourceType, InitialActionProperties, InitialActionPropertiesForPredefinedScope}, session::Session}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListActionsResponseBody};

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
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;

  // Give the user access to the "slashstep.apps.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_actions_action = Action::get_by_name("slashstep.actions.create", &mut postgres_client).await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &create_actions_action.id, &AccessPolicyPermissionLevel::User).await?;

  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  let response_action: Action = response.json();
  assert_eq!(initial_action_properties.name, response_action.name);
  assert_eq!(initial_action_properties.display_name, response_action.display_name);
  assert_eq!(initial_action_properties.description, response_action.description);
  assert_eq!(dummy_app.id, response_action.parent_app_id.expect("Parent app ID is not set."));
  assert_eq!(response_action.parent_resource_type, ActionParentResourceType::App);

  return Ok(());
  
}

/// Verifies that the server returns a 400 status code when the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_json_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;
  initialize_predefined_roles(&mut postgres_client).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "name": true,
      "display_name": "true",
      "description": false,
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 400);
  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;
  initialize_predefined_roles(&mut postgres_client).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 401);
  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_creating_resource() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;
  initialize_predefined_roles(&mut postgres_client).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  
  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/apps/{}/actions", dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
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
  initialize_required_tables(&mut test_environment.postgres_pool.get().await?).await?;
  initialize_predefined_actions(&mut test_environment.postgres_pool.get().await?).await?;
  initialize_predefined_roles(&mut test_environment.postgres_pool.get().await?).await?;

  let initial_action_properties = InitialActionPropertiesForPredefinedScope {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string()
  };

  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let response = test_server.post(&format!("/apps/{}/actions", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!(initial_action_properties))
    .await;
  
  assert_eq!(response.status_code(), 404);
  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_predefined_actions(&mut postgres_client).await?;
  
  // Give the user access to the "slashstep.actions.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_session(&user.id).await?;
  let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &mut postgres_client).await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &get_actions_action.id, &AccessPolicyPermissionLevel::User).await?;

  // Give the user access to the "slashstep.actions.list" action.
  let list_actions_action = Action::get_by_name("slashstep.actions.list", &mut postgres_client).await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &list_actions_action.id, &AccessPolicyPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_app = test_environment.create_random_app().await?;
  let dummy_action = test_environment.create_random_action(&Some(dummy_app.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.postgres_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/apps/{}/actions", &dummy_app.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 200);

  let response_body: ListActionsResponseBody = response.json();
  assert_eq!(response_body.total_count, 1);
  assert_eq!(response_body.actions.len(), 1);

  let query = format!("parent_app_id = {}", quote_literal(&dummy_app.id.to_string()));
  let actual_action_count = Action::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.total_count, actual_action_count);

  let actual_access_policies = Action::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_body.actions.len(), actual_access_policies.len());
  assert_eq!(response_body.actions[0].id, actual_access_policies[0].id);
  assert_eq!(response_body.actions[0].id, dummy_action.id);

  return Ok(());

}

// /// Verifies that the router can return a 200 status code and the requested access policy list.
// #[tokio::test]
// async fn verify_returned_access_policy_list_with_query() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
  
//   // Give the user access to the "slashstep.accessPolicies.get" action.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_session(&user.id).await?;
//   let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
//   let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &get_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Give the user access to the "slashstep.accessPolicies.list" action.
//   let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &list_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Create a few dummy access policies.
//   let dummy_action = test_environment.create_random_action(&None).await?;
//   create_action_access_policy(&mut postgres_client, &dummy_action.id, &user.id, &list_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   let shown_access_policy = create_action_access_policy(&mut postgres_client, &dummy_action.id, &user.id, &get_access_policies_action.id, &AccessPolicyPermissionLevel::Editor).await?;

//   // Set up the server and send the request.
//   let additional_query = format!("permission_level = 'Editor'");
//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.get(&format!("/actions/{}/access-policies", &dummy_action.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
//     .add_query_param("query", &additional_query)
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), 200);

//   let response_access_policies: ListAccessPolicyResponseBody = response.json();
//   assert_eq!(response_access_policies.total_count, 1);
//   assert_eq!(response_access_policies.access_policies.len(), 1);

//   let query = format!("scoped_resource_type = 'Action' AND scoped_action_id = {} and permission_level = 'Editor'", quote_literal(&dummy_action.id.to_string()));
//   let actual_access_policy_count = AccessPolicy::count(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await?;
//   assert_eq!(response_access_policies.total_count, actual_access_policy_count);

//   let actual_access_policies = AccessPolicy::list(&query, &mut postgres_client, Some(&IndividualPrincipal::User(user.id))).await?;
//   assert_eq!(response_access_policies.access_policies.len(), actual_access_policies.len());
//   assert_eq!(response_access_policies.access_policies[0].id, actual_access_policies[0].id);
//   assert_eq!(response_access_policies.access_policies[0].id, shown_access_policy.id);

//   return Ok(());

// }

// /// Verifies that the default access policy list limit is enforced.
// #[tokio::test]
// async fn verify_default_access_policy_list_limit() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
  
//   // Give the user access to the "slashstep.accessPolicies.get" action.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_session(&user.id).await?;
//   let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
//   let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &get_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Give the user access to the "slashstep.accessPolicies.list" action.
//   let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &list_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Create dummy access policies.
//   let dummy_action = test_environment.create_random_action(&None).await?;
//   for _ in 0..(DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1) {

//     let random_action = test_environment.create_random_action(&None).await?;
//     let random_user = test_environment.create_random_user().await?;
//     create_action_access_policy(&mut postgres_client, &dummy_action.id, &random_user.id, &random_action.id, &AccessPolicyPermissionLevel::User).await?;

//   }

//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.get(&format!("/actions/{}/access-policies", &dummy_action.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   assert_eq!(response.status_code(), StatusCode::OK);

//   let response_body: ListAccessPolicyResponseBody = response.json();
//   assert_eq!(response_body.access_policies.len(), DEFAULT_ACCESS_POLICY_LIST_LIMIT as usize);

//   return Ok(());

// }

// /// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
// #[tokio::test]
// async fn verify_maximum_access_policy_list_limit() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_session(&user.id).await?;
//   let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
//   let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &get_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;
//   let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &list_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.get(&format!("/actions/{}/access-policies", &get_access_policies_action.id))
//     .add_query_param("query", format!("LIMIT {}", DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

//   return Ok(());

// }

// /// Verifies that the server returns a 400 status code when the query is invalid.
// #[tokio::test]
// async fn verify_query_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
  
//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_session(&user.id).await?;
//   let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
//   let get_access_policies_action = Action::get_by_name("slashstep.accessPolicies.get", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &get_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   let list_access_policies_action = Action::get_by_name("slashstep.accessPolicies.list", &mut postgres_client).await?;
//   create_instance_access_policy(&mut postgres_client, &user.id, &list_access_policies_action.id, &AccessPolicyPermissionLevel::User).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let requests = vec![
//     test_server.get(&format!("/actions/{}/access-policies", get_access_policies_action.id))
//       .add_query_param("query", format!("action_ied = {}", get_access_policies_action.id)),
//     test_server.get(&format!("/actions/{}/access-policies", get_access_policies_action.id))
//       .add_query_param("query", format!("SELECT * FROM access_policies")),
//     test_server.get(&format!("/actions/{}/access-policies", get_access_policies_action.id))
//       .add_query_param("query", format!("1 = 1")),
//     test_server.get(&format!("/actions/{}/access-policies", get_access_policies_action.id))
//       .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
//     test_server.get(&format!("/actions/{}/access-policies", get_access_policies_action.id))
//       .add_query_param("query", format!("SELECT * FROM access_policies WHERE action_id = {}", get_access_policies_action.id))
//   ];
  
//   for request in requests {

//     let response = request
//       .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//       .await;

//     // Verify the response.
//     assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

//   }

//   return Ok(());

// }

// /// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
// #[tokio::test]
// async fn verify_authentication_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
//   initialize_predefined_roles(&mut postgres_client).await?;

//   // Create a dummy action.
//   let dummy_action = test_environment.create_random_action(&None).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.get(&format!("/actions/{}/access-policies", &dummy_action.id))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

//   return Ok(());

// }

// /// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
// #[tokio::test]
// async fn verify_permission_when_listing_access_policies() -> Result<(), TestSlashstepServerError> {

//   let test_environment = TestEnvironment::new().await?;
//   let mut postgres_client = test_environment.postgres_pool.get().await?;
//   initialize_required_tables(&mut postgres_client).await?;
//   initialize_predefined_actions(&mut postgres_client).await?;
//   initialize_predefined_roles(&mut postgres_client).await?;

//   // Create the user and the session.
//   let user = test_environment.create_random_user().await?;
//   let session = test_environment.create_session(&user.id).await?;
//   let json_web_token_private_key = Session::get_json_web_token_private_key().await?;
//   let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

//   // Create a dummy action.
//   let dummy_action = test_environment.create_random_action(&None).await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.postgres_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .layer(middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request))
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.get(&format!("/actions/{}/access-policies", &dummy_action.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

//   return Ok(());

// }