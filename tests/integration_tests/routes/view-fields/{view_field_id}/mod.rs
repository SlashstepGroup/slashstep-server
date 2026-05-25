/**
 *
 * Any test cases for /view-fields/{view_field_id} should be handled here.
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
        ResourceError, access_policy::PermissionLevel, action::Action, view_field::{EditableViewFieldProperties, ViewField}
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
};
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use ntest::timeout;
use reqwest::StatusCode;
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

    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
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
    let get_view_fields_action =
        Action::get_by_name("viewFields.get", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &get_view_fields_action.id, &PermissionLevel::User)
        .await?;

    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;

    let response = test_server
        .get(&format!("/view-fields/{}", view_field.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let get_view_field_response_body = response.json::<GetResourceResponseBody<ViewField>>();
    let response_view_field = get_view_field_response_body.data;
    assert_eq!(response_view_field.id, view_field.id);
    assert_eq!(
        response_view_field.parent_view_id,
        view_field.parent_view_id
    );
    assert_eq!(response_view_field.field_id, view_field.field_id);
    assert_eq!(
        response_view_field.next_view_field_id,
        view_field.next_view_field_id
    );

    return Ok(());
}

/// Verifies that the router can return a 400 if the view field ID is not a UUID.
#[tokio::test]
async fn verify_uuid_when_getting_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };

    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.get("/view-fields/not-a-uuid").await;

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

    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;

    let response = test_server
        .get(&format!("/view-fields/{}", view_field.id))
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
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/view-fields/{}", view_field.id))
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .get(&format!("/view-fields/{}", uuid::Uuid::now_v7()))
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

    // Grant access to the "viewFields.delete" action to the user.
    let delete_view_fields_action =
        Action::get_by_name("viewFields.delete", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(
            &user.id,
            &delete_view_fields_action.id,
            &PermissionLevel::User,
        )
        .await?;

    // Set up the server and send the request.
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/view-fields/{}", view_field.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    match ViewField::get_by_id(&view_field.id, &test_environment.database_pool)
        .await
        .expect_err("Expected an view field not found error.")
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

    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);

    let response = test_server.delete("/view-fields/not-a-uuid").await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    return Ok(());
}

/// Verifies that the router can return a 401 status code if the user needs authentication.
#[tokio::test]
async fn verify_authentication_when_deleting_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create a dummy app.
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/view-fields/{}", view_field.id))
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
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;

    // Set up the server and send the request.
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/view-fields/{}", view_field.id))
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .delete(&format!("/view-fields/{}", uuid::Uuid::now_v7()))
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
        Action::get_by_name("viewFields.update", &test_environment.database_pool).await?;
    test_environment
        .create_server_access_policy(&user.id, &update_fields_action.id, &PermissionLevel::User)
        .await?;

    // Set up the server and send the request.
    let original_view_field = test_environment
        .create_random_view_field(None, None)
        .await?;
    let next_view_field = test_environment
        .create_random_view_field(Some(&original_view_field.parent_view_id), None)
        .await?;
    let updated_view_field_properties = EditableViewFieldProperties {
        next_view_field_id: Some(Some(next_view_field.id)),
    };

    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/view-fields/{}", original_view_field.id))
        .add_cookie(Cookie::new(
            "session_access_token",
            &session_token,
        ))
        .json(&serde_json::json!(updated_view_field_properties))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::OK);

    let patch_view_field_response_body: PatchResourceResponseBody<ViewField> = response.json();
    let updated_view_field = patch_view_field_response_body.data;
    assert_eq!(original_view_field.id, updated_view_field.id);
    assert_eq!(
        original_view_field.parent_view_id,
        updated_view_field.parent_view_id
    );
    assert_eq!(original_view_field.field_id, updated_view_field.field_id);
    assert_eq!(
        updated_view_field.next_view_field_id,
        updated_view_field.next_view_field_id
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server.patch("/view-fields/not-a-uuid").await;

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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/view-fields/not-a-uuid")
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/view-fields/{}", Uuid::now_v7()))
        .add_header("Content-Type", "application/json")
        .json(&serde_json::json!({
          "next_view_field_id": false,
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch("/view-fields/not-a-uuid")
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
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/view-fields/{}", view_field.id))
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
    let view_field = test_environment
        .create_random_view_field(None, None)
        .await?;
    let state = AppState {
        database_pool: test_environment.database_pool.clone(),
        redis_pool: test_environment.redis_pool.clone(),
    };
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/view-fields/{}", view_field.id))
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
    let router = slashstep_server::routes::view_fields::view_field_id::get_router(state.clone())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    let test_server = TestServer::new(router);
    let response = test_server
        .patch(&format!("/view-fields/{}", Uuid::now_v7()))
        .json(&serde_json::json!({
          "display_name": Uuid::now_v7().to_string()
        }))
        .await;

    // Verify the response.
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    return Ok(());
}
