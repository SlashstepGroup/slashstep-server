use crate::test_utilities::{integration_test_environment::IntegrationTestEnvironment, test_slashstep_server_error::TestSlashstepServerError};
use slashstep_server::{
    AppState, get_json_web_token_private_key, initialize_required_tables,
    predefinitions::{
        initialize_predefined_actions, initialize_predefined_configurations,
        initialize_predefined_groups, initialize_predefined_roles,
    },
    resources::{
        ResourceType,
        access_policy::{
            AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties, PermissionLevel,
        },
        action::Action,
        group::{Group, GroupParentResourceType, PredefinedGroupType},
        session::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, DEFAULT_RESOURCE_LIST_LIMIT, Session},
    },
    routes::{CreateResourceResponseBody, ListResourcesResponseBody, sessions::LoginCredentials},
};
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use pg_escape::quote_literal;
use reqwest::StatusCode;
/**
 *
 * Any test cases for /sessions should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "apps.create" action.
    let create_sessions_action =
        Action::get_by_name("sessions.create", &test_environment.database_pool).await?;
    let anonymous_users_group = Group::get_protected_group_by_type(
        &GroupParentResourceType::Server,
        None,
        &PredefinedGroupType::AnonymousUsers,
        &test_environment.database_pool,
    )
    .await?;
    AccessPolicy::create(
        &InitialAccessPolicyProperties {
            principal_type: AccessPolicyPrincipalType::Group,
            principal_group_id: Some(anonymous_users_group.id),
            action_id: create_sessions_action.id,
            permission_level: PermissionLevel::User,
            scoped_resource_type: ResourceType::Server,
            is_inheritance_enabled: true,
            ..Default::default()
        },
        &test_environment.database_pool,
    )
    .await?;

    // Create a dummy resource.
    let plain_text_password = Uuid::now_v7().to_string();
    let dummy_user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    let login_credentials = LoginCredentials {
        username: dummy_user
            .username
            .expect("User should have a username.")
            .clone(),
        password: plain_text_password,
    };
    test_environment
        .create_server_access_policy(
            &dummy_user.id,
            &create_sessions_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .post("/sessions")
        .json(&serde_json::json!(login_credentials))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let create_session_response_body: CreateResourceResponseBody<Session> = response.json();
    let session = create_session_response_body.data;
    assert_eq!(dummy_user.id, session.user_id);
    assert_eq!(
        IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)),
        session.creation_ip_address
    );
    // TODO: Add assertions for expiration date

    return Ok(());
}

/// Verifies that the server returns a 400 status code when the request body is not valid JSON.
#[tokio::test]
async fn verify_request_body_json_when_creating_resource() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .post("/sessions")
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "username": true,
          "password": 123
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_creating_resource() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let create_sessions_action =
        Action::get_by_name("sessions.create", &test_environment.database_pool).await?;
    let anonymous_users_group = Group::get_protected_group_by_type(
        &GroupParentResourceType::Server,
        None,
        &PredefinedGroupType::AnonymousUsers,
        &test_environment.database_pool,
    )
    .await?;
    AccessPolicy::create(
        &InitialAccessPolicyProperties {
            principal_type: AccessPolicyPrincipalType::Group,
            principal_group_id: Some(anonymous_users_group.id),
            action_id: create_sessions_action.id,
            permission_level: PermissionLevel::User,
            scoped_resource_type: ResourceType::Server,
            is_inheritance_enabled: true,
            ..Default::default()
        },
        &test_environment.database_pool,
    )
    .await?;

    // Create the user.
    let plain_text_password = Uuid::now_v7().to_string();
    let dummy_user = test_environment
        .create_random_user(Some(&plain_text_password))
        .await?;
    test_environment
        .create_server_access_policy(
            &dummy_user.id,
            &create_sessions_action.id,
            &PermissionLevel::None,
        )
        .await?;
    let login_credentials = LoginCredentials {
        username: dummy_user
            .username
            .expect("User should have a username.")
            .clone(),
        password: plain_text_password,
    };

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .post(&format!("/sessions"))
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!(login_credentials))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    return Ok(());
}

/// Verifies that the router can return a 200 status code and the requested list.
#[tokio::test]
async fn verify_returned_list_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "sessions.get" action to the user.
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

    // Create a dummy delegation policy.
    test_environment.create_random_session(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/sessions"))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<Session> = response.json();
    assert!(response_json.total_count > 0);
    assert!(response_json.data.len() > 0);

    let actual_session_count = Session::count(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.total_count, actual_session_count);

    let actual_sessions = Session::list(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.data.len(), actual_sessions.len());

    for actual_session in actual_sessions {
        let found_access_policy = response_json
            .data
            .iter()
            .find(|session| session.id == actual_session.id);
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
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Grant access to the "apps.list" action to the user.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Create a dummy delegation policy.
    let dummy_session = test_environment.create_random_session(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let query = format!("id = {}", quote_literal(&dummy_session.id.to_string()));
    let response = test_server
        .get(&format!("/sessions"))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .add_query_param("query", &query)
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let response_json: ListResourcesResponseBody<Session> = response.json();
    assert!(response_json.total_count > 0);
    assert!(response_json.data.len() > 0);

    let actual_session_count = Session::count(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.total_count, actual_session_count);

    let actual_sessions = Session::list(
        &query,
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;
    assert_eq!(response_json.data.len(), actual_sessions.len());

    for actual_session in actual_sessions {
        let found_action = response_json
            .data
            .iter()
            .find(|session| session.id == actual_session.id);
        assert!(found_action.is_some());
    }

    return Ok(());
}

/// Verifies that there's a default list limit.
#[tokio::test]
#[timeout(40000)]
async fn verify_default_list_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "sessions.get" action to the user.
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

    // Create dummy delegation policies.
    let session_count = Session::count("", &test_environment.database_pool, None, None).await?;
    for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT - session_count + 1) {
        test_environment
            .create_random_session(Some(&user.id))
            .await?;
    }

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get("/sessions")
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;
    let get_sessions_action =
        Action::get_by_name("sessions.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Grant access to the "apps.list" action to the user.
    let list_sessions_action =
        Action::get_by_name("sessions.list", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &list_sessions_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/sessions"))
        .add_query_param(
            "query",
            format!("limit {}", DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT + 1),
        )
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_validity() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Grant access to the "sessions.get" action to the user.
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

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let bad_requests = vec![
        test_server.get(&format!("/sessions")).add_query_param(
            "query",
            format!(
                "id ~ {}",
                quote_literal(&get_sessions_action.id.to_string())
            ),
        ),
        test_server
            .get(&format!("/sessions"))
            .add_query_param("query", format!("SELECT * FROM sessions")),
        test_server
            .get(&format!("/sessions"))
            .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
        test_server.get(&format!("/sessions")).add_query_param(
            "query",
            format!(
                "id = null; SELECT * FROM sessions WHERE id = {}",
                quote_literal(&get_sessions_action.id.to_string())
            ),
        ),
    ];

    for request in bad_requests {
        let response = request
            .add_cookie(Cookie::new(
                "session_access_token",
                &session_token,
            ))
            .await;

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }

    let unprocessable_entity_requests = vec![
        test_server
            .get(&format!("/sessions"))
            .add_query_param("query", format!("1 = 1")),
    ];

    for request in unprocessable_entity_requests {
        let response = request
            .add_cookie(Cookie::new(
                "session_access_token",
                &session_token,
            ))
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
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.get(&format!("/sessions")).await;

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
    let router = super::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/sessions"))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    return Ok(());
}
