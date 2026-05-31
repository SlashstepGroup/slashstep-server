/*
 *
 * Any test cases for /sessions/{user_id}/sessions should be handled here.
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
use pg_escape::quote_literal;
use reqwest::StatusCode;
use slashstep_server::{
    AppState, get_json_web_token_private_key,
    resources::{
        access_policy::{AccessPolicyPrincipalType, PermissionLevel},
        action::Action,
        session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, Session},
    },
    routes::ListResourcesResponseBody,
};
use std::net::SocketAddr;
use uuid::Uuid;

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "sessions.get" action.
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
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Give the user access to the "sessions.list" action.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create dummy resources.
    let dummy_session = test_environment.create_random_session(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_session.user_id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_body: ListResourcesResponseBody<Session> = response.json();
    assert_eq!(response_body.total_count, 1);
    assert_eq!(response_body.data.len(), 1);

    let query = format!(
        "user_id = {}",
        quote_literal(&dummy_session.user_id.to_string())
    );
    let actual_session_count = Session::count(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_body.total_count, actual_session_count);

    let actual_sessions = Session::list(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_body.data.len(), actual_sessions.len());
    assert_eq!(response_body.data[0].id, actual_sessions[0].id);
    assert_eq!(response_body.data[0].id, dummy_session.id);

    return Ok(());
}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_with_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "sessions.get" action.
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
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Give the user access to the "sessions.list" action.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create dummy resources.
    let dummy_session = test_environment.create_random_session(None).await?;

    // Set up the server and send the request.
    let additional_query = format!("id = {}", quote_literal(&dummy_session.id.to_string()));
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_session.user_id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .add_query_param("query", &additional_query)
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_body: ListResourcesResponseBody<Session> = response.json();
    assert_eq!(response_body.total_count, 1);
    assert_eq!(response_body.data.len(), 1);

    let query = format!(
        "user_id = {} AND ({})",
        quote_literal(&dummy_session.user_id.to_string()),
        &additional_query
    );
    let actual_session_count = Session::count(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_body.total_count, actual_session_count);

    let actual_sessions = Session::list(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_body.data.len(), actual_sessions.len());
    assert_eq!(response_body.data[0].id, actual_sessions[0].id);
    assert_eq!(response_body.data[0].id, dummy_session.id);

    return Ok(());
}

/// Verifies that there's a default list limit.
#[tokio::test]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "sessions.get" action to the user.
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
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Grant access to the "sessions.list" action to the user.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create dummy resources.
    let dummy_user = test_environment.create_random_user(None).await?;
    let session_count = Session::count(
        format!("user_id = {}", quote_literal(&dummy_user.id.to_string())).as_str(),
        &test_environment.database_pool,
        None,
        None,
    )
    .await?;
    for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - session_count + 1) {
        test_environment
            .create_random_session(Some(&dummy_user.id))
            .await?;
    }

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_user.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_body: ListResourcesResponseBody<Session> = response.json();
    assert_eq!(
        response_body.data.len(),
        DEFAULT_RESOURCE_LIST_LIMIT as usize
    );

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "sessions.get" action to the user.
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
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Grant access to the "sessions.list" action to the user.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create dummy resources.
    let dummy_user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_user.id))
        .add_query_param(
            "query",
            format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1),
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

    // Grant access to the "sessions.get" action to the user.
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
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Grant access to the "sessions.list" action to the user.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create dummy resources.
    let dummy_user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };

    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let bad_requests = vec![
        test_server
            .get(&format!("/users/{}/sessions", &dummy_user.id))
            .add_query_param("query", format!("SELECT * FROM sessions")),
        test_server
            .get(&format!("/users/{}/sessions", &dummy_user.id))
            .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
        test_server
            .get(&format!("/users/{}/sessions", &dummy_user.id))
            .add_query_param(
                "query",
                format!(
                    "SELECT * FROM sessions WHERE id = {}",
                    get_sessions_action.id
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
            .get(&format!("/users/{}/sessions", &dummy_user.id))
            .add_query_param("query", format!("app_ied = {}", get_sessions_action.id)),
        test_server
            .get(&format!("/users/{}/sessions", &dummy_user.id))
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

    // Create dummy resources.
    let dummy_user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_user.id))
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

    // Create dummy resources.
    let dummy_user = test_environment.create_random_user(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &dummy_user.id))
        .add_query_param(
            "query",
            format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1),
        )
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    return Ok(());
}

/// Verifies that the server returns a 404 status code when the parent resource is not found.
#[tokio::test]
async fn verify_parent_resource_not_found_when_listing_resources()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
        opensearch_client: test_environment.opensearch_client.clone(),
    };
    let router = slashstep_server::routes::users::user_id::sessions::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/users/{}/sessions", &Uuid::now_v7()))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}
