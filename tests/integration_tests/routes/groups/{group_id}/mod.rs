/**
 *
 * Any test cases for /groups/{group_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use crate::test_utilities::{integration_test_environment::IntegrationTestEnvironment, test_slashstep_server_error::TestSlashstepServerError};
use slashstep_server::{
    AppState, get_json_web_token_private_key, resources::{
        ResourceError, access_policy::PermissionLevel, action::Action, configuration::{Configuration, EditableConfigurationProperties}, group::{EditableGroupProperties, Group}
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
};
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use reqwest::StatusCode;
use rust_decimal::Decimal;
use std::net::SocketAddr;
use uuid::Uuid;

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[path = "./membership-invitations/mod.rs"]
mod membership_invitations;
mod memberships;
mod roles;

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
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
    let get_groups_action =
        Action::get_by_name("groups.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_groups_action.id, &PermissionLevel::User)
        .await?;

    let group = test_environment.create_random_group().await?;

    // testing rate limits
    let response = test_server
        .get(&format!("/groups/{}", group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_group_response_body = response.json::<GetResourceResponseBody<Group>>();
    let response_group = get_group_response_body.data;
    assert_eq!(response_group.id, group.id);
    assert_eq!(response_group.name, group.name);
    assert_eq!(response_group.display_name, group.display_name);
    assert_eq!(response_group.description, group.description);

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

    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/groups/not-a-uuid").await;

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

    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let group = test_environment.create_random_group().await?;

    let response = test_server.get(&format!("/groups/{}", group.id)).await;

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
    let group = test_environment.create_random_group().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/groups/{}", group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/groups/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Grant access to the "groups.delete" action to the user.
    let delete_groups_action =
        Action::get_by_name("groups.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &delete_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let group = test_environment.create_random_group().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/groups/{}", group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match Group::get_by_id(&group.id, &test_environment.database_pool)
        .await
        .expect_err("Expected a group not found error.")
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

    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/groups/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let group = test_environment.create_random_group().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.delete(&format!("/groups/{}", group.id)).await;

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

    // Create a dummy group.
    let group = test_environment.create_random_group().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/groups/{}", group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/groups/{}", uuid::Uuid::now_v7()))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    let update_groups_action =
        Action::get_by_name("groups.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let original_group = test_environment.create_random_group().await?;
    let updated_group_properties = EditableGroupProperties {
        name: Some(Uuid::now_v7().to_string().replace("-", "")),
        display_name: Some(Uuid::now_v7().to_string()),
        description: Some(Some(Uuid::now_v7().to_string())),
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", original_group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_group_response_body: PatchResourceResponseBody<Group> = response.json();
    let updated_group = patch_group_response_body.data;
    assert_eq!(updated_group.id, original_group.id);
    assert_eq!(updated_group.name, updated_group_properties.name.unwrap());
    assert_eq!(
        updated_group.display_name,
        updated_group_properties.display_name.unwrap()
    );
    assert_eq!(
        updated_group.description,
        updated_group_properties.description.unwrap()
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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/groups/not-a-uuid").await;

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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/groups/not-a-uuid")
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

    // Create a dummy delegation policy to patch.
    let group = test_environment.create_random_group().await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", group.id))
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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/groups/not-a-uuid")
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({}))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_patching_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Set up the server and send the request.
    let group = test_environment.create_random_group().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", group.id))
        .json(&serde_json::json!({}))
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
    let group = test_environment.create_random_group().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!({}))
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
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", Uuid::now_v7()))
        .json(&serde_json::json!({}))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the group name is over the maximum length.
#[tokio::test]
async fn verify_group_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "groups.create" action.
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
    let create_groups_action =
        Action::get_by_name("groups.create", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &create_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let maximum_group_name_length_configuration =
        Configuration::get_by_name("groups.maximumNameLength", &test_environment.database_pool)
            .await?;
    maximum_group_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_group = test_environment.create_random_group().await?;
    let updated_group_properties = EditableGroupProperties {
        name: Some(Uuid::now_v7().to_string().replace("-", "")),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", dummy_group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the group display name is over the maximum length.
#[tokio::test]
async fn verify_group_display_name_is_at_most_at_maximum_length()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "groups.update" action.
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
    let update_groups_action =
        Action::get_by_name("groups.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let dummy_group = test_environment.create_random_group().await?;
    let maximum_group_display_name_length_configuration = Configuration::get_by_name(
        "groups.maximumDisplayNameLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_group_display_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let updated_group_properties = EditableGroupProperties {
        display_name: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", dummy_group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the group description is over the maximum length.
#[tokio::test]
async fn verify_group_description_is_at_most_at_maximum_length()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "groups.update" action.
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
    let update_groups_action =
        Action::get_by_name("groups.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let dummy_group = test_environment.create_random_group().await?;
    let maximum_group_description_length_configuration = Configuration::get_by_name(
        "groups.maximumDescriptionLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_group_description_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let updated_group_properties = EditableGroupProperties {
        description: Some(Some(Uuid::now_v7().to_string().replace("-", ""))),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", dummy_group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the group name doesn't match the allowed regex pattern.
#[tokio::test]
async fn verify_group_name_matches_regex() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "apps.create" action.
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
    let create_groups_action =
        Action::get_by_name("groups.create", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &create_groups_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let group_name_regex_configuration =
        Configuration::get_by_name("groups.allowedNameRegex", &test_environment.database_pool)
            .await?;
    group_name_regex_configuration
        .update(
            &EditableConfigurationProperties {
                text_value: Some("^$".to_string()), // This regex pattern doesn't allow any names, so this should cause a validation error.
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_group = test_environment.create_random_group().await?;
    let updated_group_properties = EditableGroupProperties {
        name: Some(Uuid::now_v7().to_string().replace("-", "")),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::groups::group_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/groups/{}", dummy_group.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}
