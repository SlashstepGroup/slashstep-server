/*
 *
 * Any test cases for /users/{user_id} should be handled here.
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
use rust_decimal::Decimal;
use slashstep_server::{
    AppState, get_json_web_token_private_key,
    resources::{
        ResourceError,
        access_policy::PermissionLevel,
        action::Action,
        configuration::{Configuration, EditableConfigurationProperties},
        user::{EditableUserPropertiesRequestBody, User},
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
};
use std::net::SocketAddr;
use uuid::Uuid;

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[path = "./oauth-authorizations/mod.rs"]
mod oauth_authorizations;
mod password;
mod sessions;

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };

    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let get_users_action =
        Action::get_by_name("users.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_users_action.id, &PermissionLevel::User)
        .await?;

    let user = test_environment.create_random_user(None).await?;

    let response = test_server
        .get(&format!("/users/{}", user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_user_response_body = response.json::<GetResourceResponseBody<User>>();
    let response_user = get_user_response_body.data;
    assert_eq!(response_user.id, user.id);
    assert_eq!(response_user.username, user.username);
    assert_eq!(response_user.display_name, user.display_name);
    assert_eq!(response_user.is_anonymous, user.is_anonymous);

    return Ok(());
}

/// Verifies that the router can return a 400 if the user ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };

    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/users/not-a-uuid").await;

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
        opensearch_client: test_environment.opensearch_client.clone(),
    };

    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let user = test_environment.create_random_user(None).await?;

    let response = test_server.get(&format!("/users/{}", user.id)).await;

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
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}", user.id))
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
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    return Ok(());
}

/// Verifies that the router can return a 204 status code if the action is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;

    // Grant access to the "users.delete" action to the user.
    let delete_users_action =
        Action::get_by_name("users.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &delete_users_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let user = test_environment.create_random_user(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/users/{}", user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match User::get_by_id(&user.id, &test_environment.database_pool)
        .await
        .expect_err("Expected an user not found error.")
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
        opensearch_client: test_environment.opensearch_client.clone(),
    };

    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/users/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.delete(&format!("/users/{}", user.id)).await;

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
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;

    // Create a dummy app.
    let user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/users/{}", user.id))
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
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/users/{}", uuid::Uuid::now_v7()))
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
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let update_fields_action =
        Action::get_by_name("users.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_fields_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let original_user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let updated_user_properties = EditableUserPropertiesRequestBody {
        username: Some(Some(Uuid::now_v7().to_string())),
        display_name: Some(Some(Uuid::now_v7().to_string())),
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", original_user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(updated_user_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_user_response_body: PatchResourceResponseBody<User> = response.json();
    let updated_user = patch_user_response_body.data;
    assert_eq!(original_user.id, updated_user.id);
    assert_eq!(
        updated_user_properties
            .username
            .expect("Expected an updated username."),
        updated_user.username
    );
    assert_eq!(
        updated_user_properties
            .display_name
            .expect("Expected an updated display name."),
        updated_user.display_name
    );
    assert_eq!(updated_user.is_anonymous, original_user.is_anonymous);

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
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/users/not-a-uuid").await;

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
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/users/not-a-uuid")
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
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", Uuid::now_v7()))
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "user_icon_id": true,
          "name": 1,
          "display_name": false,
          "description": 1,
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
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/users/not-a-uuid")
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "display_name": Uuid::now_v7().to_string()
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
    let user = test_environment.create_random_user(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", user.id))
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
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user and the session.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;

    // Set up the server and send the request.
    let user = test_environment.create_random_user(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
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
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", Uuid::now_v7()))
        .json(&serde_json::json!({
          "display_name": Uuid::now_v7().to_string()
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the username is over the maximum length.
#[tokio::test]
async fn verify_user_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "users.update" action.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let update_users_action =
        Action::get_by_name("users.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_users_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let maximum_user_name_length_configuration =
        Configuration::get_by_name("users.maximumNameLength", &test_environment.database_pool)
            .await?;
    maximum_user_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_user = test_environment.create_random_user(None).await?;
    let updated_user_properties = EditableUserPropertiesRequestBody {
        username: Some(Some(Uuid::now_v7().to_string())),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", dummy_user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(updated_user_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

#[tokio::test]
async fn verify_user_name_matches_regex() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "users.create" action.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let create_users_action =
        Action::get_by_name("users.create", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &create_users_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let user_name_regex_configuration =
        Configuration::get_by_name("users.allowedNameRegex", &test_environment.database_pool)
            .await?;
    user_name_regex_configuration
        .update(
            &EditableConfigurationProperties {
                text_value: Some("^$".to_string()), // This regex pattern doesn't allow any user names, so this should cause a validation error.
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_user = test_environment.create_random_user(None).await?;
    let editable_user_properties = EditableUserPropertiesRequestBody {
        username: Some(Some(Uuid::now_v7().to_string())),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", dummy_user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(editable_user_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the user display name is over the maximum length.
#[tokio::test]
async fn verify_user_display_name_is_at_most_at_maximum_length()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "users.update" action.
    let plain_text_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let session_credential = test_environment
        .create_random_session_credential(None, Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session_credential
        .generate_access_token(&json_web_token_private_key)
        .await?;
    let update_users_action =
        Action::get_by_name("users.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_users_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let maximum_user_display_name_length_configuration = Configuration::get_by_name(
        "users.maximumDisplayNameLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_user_display_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_user = test_environment.create_random_user(None).await?;
    let updated_user_properties = EditableUserPropertiesRequestBody {
        display_name: Some(Some(Uuid::now_v7().to_string())),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/users/{}", dummy_user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(updated_user_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}
