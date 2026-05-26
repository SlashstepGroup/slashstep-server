/*
 *
 * Any test cases for /items/{item_id} should be handled here.
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
        item::{EditableItemProperties, Item},
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
};
use std::net::SocketAddr;
use uuid::Uuid;

#[path = "./access-policies/mod.rs"]
mod access_policies;
#[path = "./field-values/mod.rs"]
mod field_values;
#[path = "./item-connections/mod.rs"]
mod item_connections;

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
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
    let get_items_action =
        Action::get_by_name("items.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_items_action.id, &PermissionLevel::User)
        .await?;

    let item = test_environment.create_random_item(None).await?;

    let response = test_server
        .get(&format!("/items/{}", item.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_item_response_body = response.json::<GetResourceResponseBody<Item>>();
    let response_item = get_item_response_body.data;
    assert_eq!(response_item.id, item.id);
    assert_eq!(response_item.summary, item.summary);
    assert_eq!(response_item.parent_project_id, item.parent_project_id);
    assert_eq!(response_item.number, item.number);

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

    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/items/not-a-uuid").await;

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

    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let item = test_environment.create_random_item(None).await?;

    let response = test_server.get(&format!("/items/{}", item.id)).await;

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
    let item = test_environment.create_random_item(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/items/{}", item.id))
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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/items/{}", uuid::Uuid::now_v7()))
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
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Grant access to the "items.delete" action to the user.
    let delete_fields_action =
        Action::get_by_name("items.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &delete_fields_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let item = test_environment.create_random_item(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/items/{}", item.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match Item::get_by_id(&item.id, &test_environment.database_pool)
        .await
        .expect_err("Expected an item not found error.")
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

    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/items/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let item = test_environment.create_random_item(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.delete(&format!("/items/{}", item.id)).await;

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
    let item = test_environment.create_random_item(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/items/{}", item.id))
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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/items/{}", uuid::Uuid::now_v7()))
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
    let update_items_action =
        Action::get_by_name("items.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_items_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let original_item = test_environment.create_random_item(None).await?;
    let updated_item_properties = EditableItemProperties {
        summary: Some(Uuid::now_v7().to_string()),
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", original_item.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(updated_item_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_item_response_body: PatchResourceResponseBody<Item> = response.json();
    let updated_item = patch_item_response_body.data;
    assert_eq!(updated_item.id, original_item.id);
    assert_eq!(
        updated_item.summary,
        updated_item_properties
            .summary
            .expect("Expected an updated summary.")
    );
    assert_eq!(
        updated_item.parent_project_id,
        original_item.parent_project_id
    );
    assert_eq!(updated_item.number, original_item.number);

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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/items/not-a-uuid").await;

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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/items/not-a-uuid")
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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", uuid::Uuid::now_v7()))
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "summary": true
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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/items/not-a-uuid")
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "summary": Some(Uuid::now_v7().to_string())
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
    let item = test_environment.create_random_item(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", item.id))
        .json(&serde_json::json!({
          "summary": Some(Uuid::now_v7().to_string())
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
    let item = test_environment.create_random_item(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", item.id))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!({
          "summary": Some(Uuid::now_v7().to_string())
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
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", Uuid::now_v7()))
        .json(&serde_json::json!({
          "summary": Some(Uuid::now_v7().to_string())
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the item summary is over the maximum length.
#[tokio::test]
async fn verify_item_summary_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError>
{
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "items.create" action.
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
    let maximum_item_summary_length_configuration = Configuration::get_by_name(
        "items.maximumSummaryLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_item_summary_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let initial_group_properties = EditableItemProperties {
        summary: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::items::item_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/items/{}", Uuid::now_v7()))
        .add_cookie(Cookie::new("session_access_token", &session_token))
        .json(&serde_json::json!(initial_group_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}
