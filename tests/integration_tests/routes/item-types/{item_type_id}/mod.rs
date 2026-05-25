/*
 *
 * Any test cases for /item-types/{item_type_id} should be handled here.
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
        ResourceError, access_policy::PermissionLevel, action::Action, configuration::{Configuration, EditableConfigurationProperties}, item_type::{EditableItemTypeProperties, ItemType}
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

/// Verifies that the router can return a 200 status code and the requested resource.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
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
    let get_item_types_action =
        Action::get_by_name("itemTypes.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_item_types_action.id, &PermissionLevel::User)
        .await?;

    let item_type = test_environment.create_random_item_type(None).await?;

    let response = test_server
        .get(&format!("/item-types/{}", item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_item_type_response_body = response.json::<GetResourceResponseBody<ItemType>>();
    let response_item_type = get_item_type_response_body.data;
    assert_eq!(response_item_type.id, item_type.id);
    assert_eq!(response_item_type.name, item_type.name);
    assert_eq!(response_item_type.display_name, item_type.display_name);
    assert_eq!(response_item_type.description, item_type.description);
    assert_eq!(
        response_item_type.item_type_icon_id,
        item_type.item_type_icon_id
    );
    assert_eq!(
        response_item_type.parent_project_id,
        item_type.parent_project_id
    );

    return Ok(());
}

/// Verifies that the router can return a 400 if the item type ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/item-types/not-a-uuid").await;

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

    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let item_type = test_environment.create_random_item_type(None).await?;

    let response = test_server
        .get(&format!("/item-types/{}", item_type.id))
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
    let item_type = test_environment.create_random_item_type(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/item-types/{}", item_type.id))
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
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/item-types/{}", uuid::Uuid::now_v7()))
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

    // Grant access to the "itemTypes.delete" action to the user.
    let delete_item_types_action =
        Action::get_by_name("itemTypes.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &delete_item_types_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let item_type = test_environment.create_random_item_type(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/item-types/{}", item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match ItemType::get_by_id(&item_type.id, &test_environment.database_pool)
        .await
        .expect_err("Expected an item type not found error.")
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

    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/item-types/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let item_type = test_environment.create_random_item_type(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/item-types/{}", item_type.id))
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
    let item_type = test_environment.create_random_item_type(None).await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/item-types/{}", item_type.id))
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
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/item-types/{}", uuid::Uuid::now_v7()))
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
    let update_fields_action =
        Action::get_by_name("itemTypes.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_fields_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let original_item_type = test_environment.create_random_item_type(None).await?;
    let updated_item_type_properties = EditableItemTypeProperties {
        name: Some(Uuid::now_v7().to_string()),
        display_name: Some(Uuid::now_v7().to_string()),
        description: Some(Some(Uuid::now_v7().to_string())),
        item_type_icon_id: None,
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", original_item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_item_type_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_item_type_response_body: PatchResourceResponseBody<ItemType> = response.json();
    let updated_item_type = patch_item_type_response_body.data;
    assert_eq!(original_item_type.id, updated_item_type.id);
    assert_eq!(
        updated_item_type_properties
            .name
            .expect("Expected an updated name."),
        updated_item_type.name
    );
    assert_eq!(
        updated_item_type_properties
            .display_name
            .expect("Expected an updated display name."),
        updated_item_type.display_name
    );
    assert_eq!(
        updated_item_type_properties
            .description
            .expect("Expected an updated description."),
        updated_item_type.description
    );
    assert_eq!(
        original_item_type.parent_project_id,
        updated_item_type.parent_project_id
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
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/item-types/not-a-uuid").await;

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
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/item-types/not-a-uuid")
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
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", Uuid::now_v7()))
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "item_type_icon_id": true,
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
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/item-types/not-a-uuid")
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
    let item_type = test_environment.create_random_item_type(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", item_type.id))
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
    let session = test_environment
        .create_random_session(Some(&user.id))
        .await?;
    let json_web_token_private_key = get_json_web_token_private_key().await?;
    let session_token = session
        .generate_access_token(&json_web_token_private_key, session.expiration_date)
        .await?;

    // Set up the server and send the request.
    let item_type = test_environment.create_random_item_type(None).await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
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
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", Uuid::now_v7()))
        .json(&serde_json::json!({
          "display_name": Uuid::now_v7().to_string()
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the item type name is over the maximum length.
#[tokio::test]
async fn verify_item_type_name_is_at_most_at_maximum_length() -> Result<(), TestSlashstepServerError>
{
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "itemTypes.update" action.
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
    let update_item_types_action =
        Action::get_by_name("itemTypes.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &update_item_types_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let maximum_item_type_name_length_configuration = Configuration::get_by_name(
        "itemTypes.maximumNameLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_item_type_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_item_type = test_environment.create_random_item_type(None).await?;
    let updated_item_type_properties = EditableItemTypeProperties {
        name: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", dummy_item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_item_type_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

#[tokio::test]
async fn verify_item_type_name_matches_regex() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "itemTypes.create" action.
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
    let create_item_types_action =
        Action::get_by_name("itemTypes.create", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &create_item_types_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let item_type_name_regex_configuration = Configuration::get_by_name(
        "itemTypes.allowedNameRegex",
        &test_environment.database_pool,
    )
    .await?;
    item_type_name_regex_configuration
        .update(
            &EditableConfigurationProperties {
                text_value: Some("^$".to_string()), // This regex pattern doesn't allow any item type names, so this should cause a validation error.
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_item_type = test_environment.create_random_item_type(None).await?;
    let editable_item_type_properties = EditableItemTypeProperties {
        name: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", dummy_item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(editable_item_type_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the item type display name is over the maximum length.
#[tokio::test]
async fn verify_item_type_display_name_is_at_most_at_maximum_length()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "itemTypes.update" action.
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
    let update_item_types_action =
        Action::get_by_name("itemTypes.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &update_item_types_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let maximum_item_type_display_name_length_configuration = Configuration::get_by_name(
        "itemTypes.maximumDisplayNameLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_item_type_display_name_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_item_type = test_environment.create_random_item_type(None).await?;
    let updated_item_type_properties = EditableItemTypeProperties {
        display_name: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", dummy_item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_item_type_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}

/// Verifies that the server returns a 422 status code when the item type description is over the maximum length.
#[tokio::test]
async fn verify_item_type_description_is_at_most_at_maximum_length()
-> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Give the user access to the "itemTypes.update" action.
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
    let update_item_types_action =
        Action::get_by_name("itemTypes.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &update_item_types_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let maximum_item_type_description_length_configuration = Configuration::get_by_name(
        "itemTypes.maximumDescriptionLength",
        &test_environment.database_pool,
    )
    .await?;
    maximum_item_type_description_length_configuration
        .update(
            &EditableConfigurationProperties {
                number_value: Some(Decimal::from(0 as i64)),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

    let dummy_item_type = test_environment.create_random_item_type(None).await?;
    let updated_item_type_properties = EditableItemTypeProperties {
        description: Some(Some(Uuid::now_v7().to_string())),
        ..Default::default()
    };
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::item_types::item_type_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/item-types/{}", dummy_item_type.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_item_type_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

    return Ok(());
}
