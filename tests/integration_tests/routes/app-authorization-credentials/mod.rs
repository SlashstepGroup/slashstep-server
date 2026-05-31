/*
 *
 * Any test cases for /app-authorization-credentials should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use reqwest::StatusCode;
use slashstep_server::{
    AppState, get_json_web_token_private_key,
    resources::{
        access_policy::{AccessPolicyPrincipalType, PermissionLevel},
        action::Action,
        app_authorization_credential::{
            AppAuthorizationCredential, DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT,
            DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
        },
    },
    routes::ListResourcesResponseBody,
};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::test_utilities::{
    integration_test_environment::IntegrationTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};

#[path = "./{app_authorization_credential_id}/mod.rs"]
mod app_authorization_credential_id;

/// Verifies that the router can return a 200 status code and the requested resource list.
#[tokio::test]
async fn verify_returned_resource_list_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "appAuthorizationCredentials.get" action to the user.
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
    let get_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.get",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "appAuthorizationCredentials.list" action to the user.
    let list_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.list",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create dummy resources.
    test_environment
        .create_random_app_authorization_credential(None, None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<AppAuthorizationCredential> = response.json();
    assert!(response_json.total_count > 0);
    assert!(response_json.data.len() > 0);

    let actual_app_authorization_credential_count = AppAuthorizationCredential::count(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(
        response_json.total_count,
        actual_app_authorization_credential_count
    );

    let actual_app_authorization_credentials = AppAuthorizationCredential::list(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(
        response_json.data.len(),
        actual_app_authorization_credentials.len()
    );

    for actual_app_authorization in actual_app_authorization_credentials {
        let found_access_policy = response_json
            .data
            .iter()
            .find(|app_authorization| app_authorization.id == actual_app_authorization.id);
        assert!(found_access_policy.is_some());
    }

    return Ok(());
}

/// Verifies that the router can return a 200 status code and the requested resource list.
#[tokio::test]
async fn verify_returned_resource_list_with_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "appAuthorizationCredentials.get" action to the user.
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
    let get_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.get",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "appAuthorizationCredentials.list" action to the user.
    let list_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.list",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create dummy resources.
    let dummy_app_authorization_credential = test_environment
        .create_random_app_authorization_credential(None, None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let query = format!(
        "app_authorization_id = \"{}\"",
        dummy_app_authorization_credential.app_authorization_id
    );
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .add_query_param("query", &query)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<AppAuthorizationCredential> = response.json();
    let actual_app_authorization_credential_count = AppAuthorizationCredential::count(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(
        response_json.total_count,
        actual_app_authorization_credential_count
    );

    let actual_app_authorization_credentials = AppAuthorizationCredential::list(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(
        response_json.data.len(),
        actual_app_authorization_credentials.len()
    );

    for actual_action in actual_app_authorization_credentials {
        let found_action = response_json
            .data
            .iter()
            .find(|action| action.id == actual_action.id);
        assert!(found_action.is_some());
    }

    return Ok(());
}

/// Verifies that there's a default resource list limit.
#[tokio::test]
async fn verify_default_resource_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "appAuthorizationCredentials.get" action to the user.
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
    let get_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.get",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "appAuthorizationCredentials.list" action to the user.
    let list_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.list",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create dummy actions.
    let app_authorization_count =
        AppAuthorizationCredential::count("", &test_environment.database_pool, None, None).await?;
    for _ in 0..(DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT - app_authorization_count + 1) {
        test_environment
            .create_random_app_authorization_credential(None, None)
            .await?;
    }

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_body: ListResourcesResponseBody<AppAuthorizationCredential> = response.json();
    assert_eq!(
        response_body.data.len(),
        DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT as usize
    );

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_resource_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "appAuthorizationCredentials.get" action to the user.
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
    let get_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.get",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "appAuthorizationCredentials.list" action to the user.
    let list_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.list",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .add_query_param(
            "query",
            format!("LIMIT {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1),
        )
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_resources() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "appAuthorizationCredentials.get" action to the user.
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
    let get_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.get",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "appAuthorizationCredentials.list" action to the user.
    let list_app_authorizations_action = Action::get_by_name(
        "appAuthorizationCredentials.list",
        &test_environment.database_pool,
    )
    .await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_app_authorizations_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let bad_requests = vec![
        test_server
            .get(&format!("/app-authorization-credentials"))
            .add_query_param(
                "query",
                format!("SELECT * FROM app_authorization_credentials"),
            ),
        test_server
            .get(&format!("/app-authorization-credentials"))
            .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
        test_server
            .get(&format!("/app-authorization-credentials"))
            .add_query_param(
                "query",
                format!(
                    "app_authorization_id = {}",
                    get_app_authorizations_action.id
                ),
            ),
    ];

    for request in bad_requests {
        let response = request
            .add_cookie(Cookie::new("session_access_token", &session_token))
            .await;

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }

    let unprocessable_entity_requests = vec![
        test_server
            .get(&format!("/app-authorization-credentials"))
            .add_query_param(
                "query",
                format!(
                    "app_authorization_ied = {}",
                    get_app_authorizations_action.id
                ),
            ),
        test_server
            .get(&format!("/app-authorization-credentials"))
            .add_query_param("query", format!("1 = 1")),
    ];

    for request in unprocessable_entity_requests {
        let response = request
            .add_cookie(Cookie::new("session_access_token", &session_token))
            .await;

        assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    return Ok(());
}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_listing_resources() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    return Ok(());
}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_resources() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a user and a session.
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
    let router = slashstep_server::routes::app_authorization_credentials::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/app-authorization-credentials"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    return Ok(());
}
