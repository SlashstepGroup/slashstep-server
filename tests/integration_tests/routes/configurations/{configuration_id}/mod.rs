/*
 *
 * Any test cases for /configurations/{configuration_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use crate::test_utilities::{
    integration_test_environment::IntegrationTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use reqwest::StatusCode;
use slashstep_server::{
    AppState, get_json_web_token_private_key,
    resources::{
        ResourceError,
        access_policy::PermissionLevel,
        action::Action,
        configuration::{Configuration, EditableConfigurationProperties},
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
};
use std::net::SocketAddr;
use uuid::Uuid;

#[path = "./access-policies/mod.rs"]
mod access_policies;

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;
    let get_configurations_action =
        Action::get_by_name("configurations.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_configurations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    let configuration = test_environment.create_random_configuration().await?;

    let response = test_server
        .get(&format!("/configurations/{}", configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_configuration_response_body = response.json::<GetResourceResponseBody<Configuration>>();
    let response_configuration = get_configuration_response_body.data;
    assert_eq!(response_configuration.id, configuration.id);
    assert_eq!(response_configuration.name, configuration.name);
    assert_eq!(response_configuration.value_type, configuration.value_type);

    return Ok(());
}

/// Verifies that the router can return a 400 if the app ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/configurations/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the requestor needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError>
{
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let configuration = test_environment.create_random_configuration().await?;

    let response = test_server
        .get(&format!("/configurations/{}", configuration.id))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    return Ok(());
}

/// Verifies that the router can return a 403 status code if the requestor does not have permission to get the app.
#[tokio::test]
#[timeout(40000)]
async fn verify_permission_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user, the session, and the action.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;
    let configuration = test_environment.create_random_configuration().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/configurations/{}", configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    return Ok(());
}

/// Verifies that the router can return a 404 status code if the requested resource doesn't exist
#[tokio::test]
#[timeout(40000)]
async fn verify_not_found_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/configurations/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    return Ok(());
}

/// Verifies that the router can return a 204 status code if the resource is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Grant access to the "configurations.delete" action to the user.
    let delete_configurations_action =
        Action::get_by_name("configurations.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &delete_configurations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let configuration = test_environment.create_random_configuration().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/configurations/{}", configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match Configuration::get_by_id(&configuration.id, &test_environment.database_pool)
        .await
        .expect_err("Expected a configuration not found error.")
    {
        ResourceError::NotFoundError(_) => {}

        error => return Err(TestSlashstepServerError::ResourceError(error)),
    }

    return Ok(());
}

/// Verifies that the router can return a 400 status code if the ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/configurations/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let configuration = test_environment.create_random_configuration().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/configurations/{}", configuration.id))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    return Ok(());
}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the resource.
#[tokio::test]
async fn verify_permission_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Create a dummy app.
    let configuration = test_environment.create_random_configuration().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/configurations/{}", configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    return Ok(());
}

/// Verifies that the router can return a 404 status code if the resource does not exist.
#[tokio::test]
async fn verify_resource_exists_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/configurations/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    return Ok(());
}

/// Verifies that the router can return a 200 status code if the resource is successfully patched.
#[tokio::test]
async fn verify_successful_patch_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;
    let update_configurations_action =
        Action::get_by_name("configurations.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &update_configurations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let original_configuration = test_environment.create_random_configuration().await?;
    let new_configuration_properties = EditableConfigurationProperties {
        name: Some(Uuid::now_v7().to_string()),
        description: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/configurations/{}", original_configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(new_configuration_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_configuration_response_body: PatchResourceResponseBody<Configuration> =
        response.json();
    let updated_configuration = patch_configuration_response_body.data;
    assert_eq!(original_configuration.id, updated_configuration.id);
    assert_eq!(
        updated_configuration.name,
        new_configuration_properties
            .name
            .expect("Expected the name to be updated.")
    );
    assert_eq!(
        updated_configuration.description,
        new_configuration_properties.description
    );

    return Ok(());
}

/// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
#[tokio::test]
async fn verify_content_type_when_patching_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/configurations/not-a-uuid").await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 400 status code if the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_exists_when_patching_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/configurations/not-a-uuid")
        .add_header("Content-Type", "application/json")
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 400 status code if the request body includes unwanted data.
#[tokio::test]
async fn verify_request_body_json_when_patching_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/configurations/{}", uuid::Uuid::now_v7()))
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
    let test_environment = IntegrationTestEnvironment::new().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/configurations/not-a-uuid")
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
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let configuration = test_environment.create_random_configuration().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/configurations/{}", configuration.id))
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
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Set up the server and send the request.
    let configuration = test_environment.create_random_configuration().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/configurations/{}", configuration.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
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
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router =
        slashstep_server::routes::configurations::configuration_id::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/configurations/{}", Uuid::now_v7()))
        .json(&serde_json::json!({
          "name": Uuid::now_v7().to_string()
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}
