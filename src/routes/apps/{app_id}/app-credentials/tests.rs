use std::net::SocketAddr;

use axum::middleware;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, ed25519::signature::rand_core::OsRng, pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding}};
use uuid::Uuid;

use crate::{AppState, initialize_required_tables, middleware::http_request_middleware, predefinitions::initialize_predefined_actions, resources::{access_policy::{AccessPolicy, AccessPolicyPermissionLevel, InitialAccessPolicyProperties}, action::Action, app_credential::{AppCredential, InitialAppCredentialPropertiesForPredefinedScope}, session::Session}, routes::apps::app_id::app_credentials::CreateAppCredentialResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

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
  let create_app_credentials_action = Action::get_by_name("slashstep.appCredentials.create", &mut postgres_client).await?;
  create_instance_access_policy(&mut postgres_client, &user.id, &create_app_credentials_action.id, &AccessPolicyPermissionLevel::User).await?;

  // Create a dummy app.
  let dummy_app = test_environment.create_random_app().await?;

  // Set up the server and send the request.
  let initial_app_credential_properties = InitialAppCredentialPropertiesForPredefinedScope {
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
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
    .json(&serde_json::json!(initial_app_credential_properties))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  let response_app_credential: CreateAppCredentialResponseBody = response.json();
  assert_eq!(initial_app_credential_properties.description, response_app_credential.description);
  assert_eq!(initial_app_credential_properties.expiration_date, response_app_credential.expiration_date);
  assert_eq!(response_app_credential.public_key.len(), 1024);
  assert_eq!(response_app_credential.private_key.len(), 1024);

  return Ok(());
  
}