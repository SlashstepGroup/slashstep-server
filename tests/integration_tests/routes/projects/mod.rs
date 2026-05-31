/*
 *
 * Any test cases for /projects should be handled here.
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
        project::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, Project},
    },
    routes::ListResourcesResponseBody,
};
use std::net::SocketAddr;
use uuid::Uuid;

#[path = "./{project_id}/mod.rs"]
mod project_id;

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "projects.get" action to the user.
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
    let get_delegation_policies_action =
        Action::get_by_name("projects.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "projects.list" action to the user.
    let list_delegation_policies_action =
        Action::get_by_name("projects.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create a dummy delegation policy.
    test_environment.create_random_project(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/projects"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<Project> = response.json();
    assert!(response_json.total_count > 0);
    assert!(response_json.data.len() > 0);

    let actual_project_count = Project::count(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.total_count, actual_project_count);

    let actual_delegation_policies = Project::list(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.data.len(), actual_delegation_policies.len());

    for actual_project in actual_delegation_policies {
        let found_access_policy = response_json
            .data
            .iter()
            .find(|project| project.id == actual_project.id);
        assert!(found_access_policy.is_some());
    }

    return Ok(());
}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_with_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "apps.get" action to the user.
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
    let get_delegation_policies_action =
        Action::get_by_name("projects.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "apps.list" action to the user.
    let list_delegation_policies_action =
        Action::get_by_name("projects.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create a dummy delegation policy.
    let dummy_project = test_environment.create_random_project(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let query = format!("id = {}", quote_literal(&dummy_project.id.to_string()));
    let response = test_server
        .get(&format!("/projects"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .add_query_param("query", &query)
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<Project> = response.json();
    assert!(response_json.total_count > 0);
    assert!(response_json.data.len() > 0);

    let actual_project_count = Project::count(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.total_count, actual_project_count);

    let actual_delegation_policies = Project::list(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.data.len(), actual_delegation_policies.len());

    for actual_project in actual_delegation_policies {
        let found_action = response_json
            .data
            .iter()
            .find(|project| project.id == actual_project.id);
        assert!(found_action.is_some());
    }

    return Ok(());
}

/// Verifies that there's a default list limit.
#[tokio::test]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "projects.get" action to the user.
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
    let get_delegation_policies_action =
        Action::get_by_name("projects.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "projects.list" action to the user.
    let list_delegation_policies_action =
        Action::get_by_name("projects.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Create dummy delegation policies.
    let project_count = Project::count("", &test_environment.database_pool, None, None).await?;
    for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - project_count + 1) {
        test_environment.create_random_project(None).await?;
    }

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/projects"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_body: ListResourcesResponseBody<Project> = response.json();
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

    // Grant access to the "projects.get" action to the user.
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
    let get_delegation_policies_action =
        Action::get_by_name("projects.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "apps.list" action to the user.
    let list_delegation_policies_action =
        Action::get_by_name("projects.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/projects"))
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
async fn verify_query_validity() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "projects.get" action to the user.
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
    let get_delegation_policies_action =
        Action::get_by_name("projects.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &get_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Grant access to the "projects.list" action to the user.
    let list_delegation_policies_action =
        Action::get_by_name("projects.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &list_delegation_policies_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let bad_requests = vec![
        test_server.get(&format!("/projects")).add_query_param(
            "query",
            format!(
                "id ~ {}",
                quote_literal(&get_delegation_policies_action.id.to_string())
            ),
        ),
        test_server
            .get(&format!("/projects"))
            .add_query_param("query", format!("SELECT * FROM delegation_policies")),
        test_server
            .get(&format!("/projects"))
            .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
        test_server.get(&format!("/projects")).add_query_param(
            "query",
            format!(
                "id = null; SELECT * FROM delegation_policies WHERE id = {}",
                quote_literal(&get_delegation_policies_action.id.to_string())
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
            .get(&format!("/projects"))
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
async fn verify_authentication() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.get(&format!("/projects")).await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    return Ok(());
}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission() -> Result<(), TestSlashstepServerError> {
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
    let router = slashstep_server::routes::projects::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/projects"))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    return Ok(());
}
