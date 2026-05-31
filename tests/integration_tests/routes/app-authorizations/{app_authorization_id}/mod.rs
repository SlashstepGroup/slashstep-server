/*
 *
 * Any test cases for /app-authorizations/{action_id} should be handled here.
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
        ResourceError, access_policy::PermissionLevel, action::Action,
        app_authorization::AppAuthorization,
    },
    routes::GetResourceResponseBody,
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

    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
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
    let get_app_authorizations_action =
        Action::get_by_name("appAuthorizations.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;

    let response = test_server
        .get(&format!("/app-authorizations/{}", app_authorization.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let get_app_authorization_response_body =
        response.json::<GetResourceResponseBody<AppAuthorization>>();
    let response_app_authorization = get_app_authorization_response_body.data;
    assert_eq!(response_app_authorization.id, app_authorization.id);
    assert_eq!(response_app_authorization.app_id, app_authorization.app_id);
    assert_eq!(
        response_app_authorization.authorizing_resource_type,
        app_authorization.authorizing_resource_type
    );
    assert_eq!(
        response_app_authorization.authorizing_project_id,
        app_authorization.authorizing_project_id
    );
    assert_eq!(
        response_app_authorization.authorizing_workspace_id,
        app_authorization.authorizing_workspace_id
    );
    assert_eq!(
        response_app_authorization.authorizing_user_id,
        app_authorization.authorizing_user_id
    );

    return Ok(());
}

/// Verifies that the router can return a 400 if the resource ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/app-authorizations/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError>
{
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;

    let response = test_server
        .get(&format!("/app-authorizations/{}", app_authorization.id))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    return Ok(());
}

/// Verifies that the router can return a 403 status code if the user does not have permission to view the resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_permission_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the user, the session, and the resource.
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
    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorizations/{}", app_authorization.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    return Ok(());
}

/// Verifies that the router can return a 404 status code if the requested resource doesn't exist.
#[tokio::test]
#[timeout(40000)]
async fn verify_not_found_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorizations/{}", uuid::Uuid::now_v7()))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    return Ok(());
}

/// Verifies that the router can return a 204 status code if the resource is successfully deleted.
#[tokio::test]
async fn verify_successful_deletion_when_deleting_resource_by_id()
-> Result<(), TestSlashstepServerError> {
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

    // Grant access to the "appAuthorizations.delete" action to the user.
    let delete_app_authorizations_action =
        Action::get_by_name("appAuthorizations.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &delete_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/app-authorizations/{}", app_authorization.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match AppAuthorization::get_by_id(&app_authorization.id, &test_environment.database_pool)
        .await
        .expect_err("expected a not found error.")
    {
        ResourceError::NotFoundError(_) => {}

        error => return Err(TestSlashstepServerError::ResourceError(error)),
    }

    return Ok(());
}

/// Verifies that the router can return a 400 status code if the resource ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/app-authorizations/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError>
{
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create dummy resources.
    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/app-authorizations/{}", app_authorization.id))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    return Ok(());
}

/// Verifies that the router can return a 403 status code if the user does not have permission to delete the resource.
#[tokio::test]
async fn verify_permission_when_deleting_resource_by_id() -> Result<(), TestSlashstepServerError> {
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

    // Create dummy resources.
    let app_authorization = test_environment
        .create_random_app_authorization(None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/app-authorizations/{}", app_authorization.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    return Ok(());
}

/// Verifies that the router can return a 404 status code if the resource does not exist.
#[tokio::test]
async fn verify_resource_exists_when_deleting_resource_by_id()
-> Result<(), TestSlashstepServerError> {
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
    };
    let router = slashstep_server::routes::app_authorizations::app_authorization_id::get_router(
        state.clone(),
    )
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/app-authorizations/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    return Ok(());
}
