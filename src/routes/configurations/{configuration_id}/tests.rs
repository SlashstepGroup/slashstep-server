/**
 * 
 * Any test cases for /configurations/{configuration_id} should be handled here.
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
use strum::IntoEnumIterator;
use uuid::Uuid;
use crate::{
  Action, AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, resources::{
    access_policy::
      ActionPermissionLevel
    , configuration::{Configuration, ConfigurationValueType, EditableConfigurationProperties},
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
  let get_configurations_action = Action::get_by_name("slashstep.configurations.get", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &get_configurations_action.id, &ActionPermissionLevel::User).await?;
  
  let configuration = test_environment.create_random_configuration().await?;

  let response = test_server.get(&format!("/configurations/{}", configuration.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_configuration: Configuration = response.json();
  assert_eq!(response_configuration.id, configuration.id);
  assert_eq!(response_configuration.name, configuration.name);
  assert_eq!(response_configuration.value_type, configuration.value_type);
  assert_eq!(response_configuration.text_value, configuration.text_value);
  assert_eq!(response_configuration.integer_value, configuration.integer_value);
  assert_eq!(response_configuration.decimal_value, configuration.decimal_value);
  assert_eq!(response_configuration.boolean_value, configuration.boolean_value);

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

  let response = test_server.get("/configurations/not-a-uuid")
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
  
  let configuration = test_environment.create_random_configuration().await?;

  let response = test_server.get(&format!("/configurations/{}", configuration.id))
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
  let configuration = test_environment.create_random_configuration().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/configurations/{}", configuration.id))
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
  let response = test_server.get(&format!("/configurations/{}", uuid::Uuid::now_v7()))
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

//   // Grant access to the "slashstep.configurations.delete" action to the user.
//   let delete_fields_action = Action::get_by_name("slashstep.configurations.delete", &test_environment.database_pool).await?;
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
//   let configuration = test_environment.create_random_configuration().await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/configurations/{}", configuration.id))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   assert_eq!(response.status_code(), 204);

//   match App::get_by_id(&configuration.id, &test_environment.database_pool).await.expect_err("Expected an app not found error.") {

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

//   let response = test_server.delete("/configurations/not-a-uuid")
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
//   let configuration = test_environment.create_random_configuration().await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/configurations/{}", configuration.id))
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
//   let configuration = test_environment.create_random_configuration().await?;

//   // Set up the server and send the request.
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };
//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router)?;
//   let response = test_server.delete(&format!("/configurations/{}", configuration.id))
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
//   let response = test_server.delete(&format!("/configurations/{}", uuid::Uuid::now_v7()))
//     .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
//     .await;
  
//   // Verify the response.
//   assert_eq!(response.status_code(), 404);
//   return Ok(());

// }

/// Verifies that the router can return a 200 status code if the resource is successfully patched.
#[tokio::test]
async fn verify_successful_patch_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let update_configurations_action = Action::get_by_name("slashstep.configurations.update", &test_environment.database_pool).await?;
  test_environment.create_instance_access_policy(&user.id, &update_configurations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let original_configuration = test_environment.create_random_configuration().await?;
  for value_type in ConfigurationValueType::iter() {

    let new_configuration_properties = EditableConfigurationProperties {
      name: Some(Uuid::now_v7().to_string()),
      value_type: Some(value_type.clone()),
      integer_value: if value_type == ConfigurationValueType::Integer { Some(rand::random()) } else { None },
      text_value: if value_type == ConfigurationValueType::Text { Some(Uuid::now_v7().to_string()) } else { None },
      decimal_value: if value_type == ConfigurationValueType::Decimal { Some(rand::random::<i32>().into()) } else { None }, // For some reason, rand::random() causes a compiler error.
      boolean_value: if value_type == ConfigurationValueType::Boolean { Some(rand::random()) } else { None },
    };

    let state = AppState {
      database_pool: test_environment.database_pool.clone(),
    };
    let router = super::get_router(state.clone())
      .with_state(state)
      .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router)?;
    let response = test_server.patch(&format!("/configurations/{}", original_configuration.id))
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .json(&serde_json::json!(new_configuration_properties))
      .await;
    
    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let updated_configuration: Configuration = response.json();
    assert_eq!(original_configuration.id, updated_configuration.id);
    assert_eq!(updated_configuration.name, new_configuration_properties.name.expect("Expected the name to be updated."));
    assert_eq!(updated_configuration.value_type, new_configuration_properties.value_type.expect("Expected the value type to be updated."));
    assert_eq!(updated_configuration.integer_value, new_configuration_properties.integer_value);
    assert_eq!(updated_configuration.text_value, new_configuration_properties.text_value);
    assert_eq!(updated_configuration.decimal_value, new_configuration_properties.decimal_value);
    assert_eq!(updated_configuration.boolean_value, new_configuration_properties.boolean_value);

  }

  return Ok(());

}

/// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
#[tokio::test]
async fn verify_content_type_when_patching_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/configurations/not-a-uuid")
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

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/configurations/not-a-uuid")
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
  
  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/configurations/{}", uuid::Uuid::now_v7()))
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "name": true
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
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch("/configurations/not-a-uuid")
    .add_header("Content-Type", "application/json")
    .json(&serde_json::json!({
      "name": Uuid::now_v7().to_string()
    }))
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
  
  // Set up the server and send the request.
  let configuration = test_environment.create_random_configuration().await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/configurations/{}", configuration.id))
    .json(&serde_json::json!({
      "name": Uuid::now_v7().to_string()
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

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Set up the server and send the request.
  let configuration = test_environment.create_random_configuration().await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/configurations/{}", configuration.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!({
      "name": Uuid::now_v7().to_string()
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

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.patch(&format!("/configurations/{}", Uuid::now_v7()))
    .json(&serde_json::json!({
      "name": Uuid::now_v7().to_string()
    }))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

  return Ok(());

}