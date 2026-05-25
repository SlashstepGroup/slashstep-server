/*
 *
 * Any end-to-end test cases for /access-policies/{access_policy_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use ntest::timeout;
use slashstep_server::{
    resources::{
        ResourceType,
        access_policy::{AccessPolicyPrincipalType, PermissionLevel},
        action::Action,
    },
    routes::access_policies::CreateServerAccessPolicyRequestBody,
};
use uuid::Uuid;

use crate::test_utilities::{
    end_to_end_test_environment::EndToEndTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};

/// Verifies that the router can return a 200 status code and the requested access policy.
#[tokio::test]
#[timeout(40000)]
async fn verify_returned_access_policy_by_id() -> Result<(), TestSlashstepServerError> {
    let mut test_environment = EndToEndTestEnvironment::new().await?;
    let user_password = Uuid::now_v7().to_string();
    let user = test_environment
        .create_random_user(Some(&user_password))
        .await?;
    let admin_password = Uuid::now_v7().to_string();
    let admin_user = test_environment
        .create_admin_user(Some(&admin_password))
        .await?;
    test_environment
        .create_session(
            &admin_user
                .username
                .expect("Expected user to have a username."),
            &admin_password,
        )
        .await?;
    let get_access_policies_action =
        Action::get_by_name("accessPolicies.get", &test_environment.database_pool).await?;
    let access_policy_properties = CreateServerAccessPolicyRequestBody {
        action_id: get_access_policies_action.id,
        permission_level: PermissionLevel::User,
        is_inheritance_enabled: true,
        principal_type: AccessPolicyPrincipalType::User,
        principal_user_id: Some(user.id),
        principal_app_id: None,
        principal_group_id: None,
        principal_role_id: None,
    };
    let created_access_policy = test_environment
        .create_server_access_policy(&access_policy_properties)
        .await?;

    test_environment.test_server.clear_cookies();
    test_environment
        .create_session(
            &user.username.expect("Expected user to have a username."),
            &user_password,
        )
        .await?;
    let retrieved_access_policy = test_environment
        .get_access_policy_by_id(&created_access_policy.id)
        .await?;

    assert_eq!(retrieved_access_policy.id, created_access_policy.id);
    assert_eq!(
        retrieved_access_policy.action_id,
        created_access_policy.action_id
    );
    assert_eq!(
        retrieved_access_policy.permission_level,
        created_access_policy.permission_level
    );
    assert_eq!(
        retrieved_access_policy.is_inheritance_enabled,
        created_access_policy.is_inheritance_enabled
    );
    assert_eq!(
        retrieved_access_policy.principal_type,
        access_policy_properties.principal_type
    );
    assert_eq!(
        retrieved_access_policy.principal_user_id,
        access_policy_properties.principal_user_id
    );
    assert_eq!(
        retrieved_access_policy.principal_group_id,
        access_policy_properties.principal_group_id
    );
    assert_eq!(
        retrieved_access_policy.principal_role_id,
        access_policy_properties.principal_role_id
    );
    assert_eq!(
        retrieved_access_policy.principal_app_id,
        access_policy_properties.principal_app_id
    );
    assert_eq!(
        retrieved_access_policy.scoped_resource_type,
        ResourceType::Server
    );
    assert_eq!(retrieved_access_policy.scoped_action_id, None);
    assert_eq!(retrieved_access_policy.scoped_app_id, None);
    assert_eq!(retrieved_access_policy.scoped_group_id, None);
    assert_eq!(retrieved_access_policy.scoped_item_id, None);
    assert_eq!(retrieved_access_policy.scoped_milestone_id, None);
    assert_eq!(retrieved_access_policy.scoped_project_id, None);
    assert_eq!(retrieved_access_policy.scoped_role_id, None);
    assert_eq!(retrieved_access_policy.scoped_user_id, None);
    assert_eq!(retrieved_access_policy.scoped_workspace_id, None);

    return Ok(());
}

// /// Verifies that the router can return a 204 status code if the access policy is successfully deleted.
// #[tokio::test]
// async fn verify_successful_deletion_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let plain_text_password = Uuid::now_v7().to_string();
//   let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
//   let delete_access_policies_action = Action::get_by_name("accessPolicies.delete", &test_environment.database_pool).await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: delete_access_policies_action.id,
//     permission_level: PermissionLevel::Editor,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: ResourceType::Server,
//     ..Default::default()
//   };
//   let access_policy = AccessPolicy::create(&access_policy_properties, &test_environment.database_pool).await?;

//   let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
//     .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

//   match AccessPolicy::get_by_id(&access_policy.id, &test_environment.database_pool).await.expect_err("Expected an access policy not found error.") {

//     ResourceError::NotFoundError(_) => {},

//     error => return Err(TestSlashstepServerError::ResourceError(error))

//   }

//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the access policy ID is not a UUID.
// #[tokio::test]
// async fn verify_uuid_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.delete("/access-policies/not-a-uuid")
//     .await;

//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 401 status code if the user needs authentication.
// #[tokio::test]
// async fn verify_authentication_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let access_policy = test_environment.create_random_access_policy().await?;

//   let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
//   return Ok(());

// }

// /// Verifies that the router can return a 403 status code if the user does not have permission to delete the access policy.
// #[tokio::test]
// async fn verify_permission_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;

//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let plain_text_password = Uuid::now_v7().to_string();
//   let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
//   let access_policy = test_environment.create_random_access_policy().await?;

//   let response = test_server.delete(&format!("/access-policies/{}", access_policy.id))
//     .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
//   return Ok(());

// }

// /// Verifies that the router can return a 404 status code if the access policy does not exist.
// #[tokio::test]
// async fn verify_access_policy_exists_when_deleting_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;

//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let plain_text_password = Uuid::now_v7().to_string();
//   let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;

//   let response = test_server.delete(&format!("/access-policies/{}", uuid::Uuid::now_v7()))
//     .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
//   return Ok(());

// }

// /// Verifies that the router can return a 200 status code if the access policy is successfully patched.
// #[tokio::test]
// async fn verify_successful_patch_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;

//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let plain_text_password = Uuid::now_v7().to_string();
//   let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
//   let get_access_policies_action = Action::get_by_name("accessPolicies.update", &test_environment.database_pool).await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: get_access_policies_action.id,
//     permission_level: PermissionLevel::Editor,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: ResourceType::Server,
//     ..Default::default()
//   };
//   let access_policy = AccessPolicy::create(&access_policy_properties, &test_environment.database_pool).await?;

//   let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
//     .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
//     .json(&serde_json::json!({
//       "permission_level": "User",
//       "is_inheritance_enabled": false
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::OK);

//   let response_body: GetResourceResponseBody<AccessPolicy> = response.json();
//   let response_access_policy = response_body.resource;
//   assert_eq!(response_access_policy.id, access_policy.id);
//   assert_eq!(response_access_policy.action_id, access_policy.action_id);
//   assert_eq!(response_access_policy.permission_level, PermissionLevel::User);
//   assert_eq!(response_access_policy.is_inheritance_enabled, false);
//   assert_eq!(response_access_policy.principal_type, access_policy.principal_type);
//   assert_eq!(response_access_policy.principal_user_id, access_policy.principal_user_id);
//   assert_eq!(response_access_policy.principal_group_id, access_policy.principal_group_id);
//   assert_eq!(response_access_policy.principal_role_id, access_policy.principal_role_id);
//   assert_eq!(response_access_policy.principal_app_id, access_policy.principal_app_id);
//   assert_eq!(response_access_policy.scoped_resource_type, access_policy.scoped_resource_type);
//   assert_eq!(response_access_policy.scoped_action_id, access_policy.scoped_action_id);
//   assert_eq!(response_access_policy.scoped_app_id, access_policy.scoped_app_id);
//   assert_eq!(response_access_policy.scoped_group_id, access_policy.scoped_group_id);
//   assert_eq!(response_access_policy.scoped_item_id, access_policy.scoped_item_id);
//   assert_eq!(response_access_policy.scoped_milestone_id, access_policy.scoped_milestone_id);
//   assert_eq!(response_access_policy.scoped_project_id, access_policy.scoped_project_id);
//   assert_eq!(response_access_policy.scoped_role_id, access_policy.scoped_role_id);
//   assert_eq!(response_access_policy.scoped_user_id, access_policy.scoped_user_id);
//   assert_eq!(response_access_policy.scoped_workspace_id, access_policy.scoped_workspace_id);

//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request doesn't have a valid content type.
// #[tokio::test]
// async fn verify_content_type_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.patch("/access-policies/not-a-uuid")
//     .await;

//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request body is not valid JSON.
// #[tokio::test]
// async fn verify_request_body_exists_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.patch("/access-policies/not-a-uuid")
//     .add_header("Content-Type", "application/json")
//     .await;

//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the request body includes unwanted data.
// #[tokio::test]
// async fn verify_request_body_json_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.patch("/access-policies/not-a-uuid")
//     .add_header("Content-Type", "application/json")
//     .json(&serde_json::json!({
//       "permission_level": "Super Duper Admin",
//       "is_inheritance_enabled": "true",
//       "principal_type": "User2",
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 400 status code if the access policy ID is not a UUID.
// #[tokio::test]
// async fn verify_uuid_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.patch("/access-policies/not-a-uuid")
//     .add_header("Content-Type", "application/json")
//     .json(&serde_json::json!({
//       "permission_level": "Editor",
//       "is_inheritance_enabled": false
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
//   return Ok(());

// }

// /// Verifies that the router can return a 401 status code if the user needs authentication.
// #[tokio::test]
// async fn verify_authentication_when_patching_access_policy_by_id() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let user = test_environment.create_random_user(None).await?;
//   let get_access_policies_action = Action::get_by_name("accessPolicies.update", &test_environment.database_pool).await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: get_access_policies_action.id,
//     permission_level: PermissionLevel::Editor,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: ResourceType::Server,
//     ..Default::default()
//   };
//   let access_policy = AccessPolicy::create(&access_policy_properties, &test_environment.database_pool).await?;

//   let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
//     .json(&serde_json::json!({
//       "permission_level": "User",
//       "is_inheritance_enabled": false
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

//   return Ok(());

// }

// /// Verifies that the router can return a 403 status code if the user does not have permission to patch the access policy.
// #[tokio::test]
// async fn verify_permission_when_patching_access_policy() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let plain_text_password = Uuid::now_v7().to_string();
//   let user = test_environment.create_random_user(Some(&plain_text_password)).await?;
//   let session = test_environment.create_random_session(Some(&user.id)).await?;
//   let json_web_token_private_key = get_json_web_token_private_key().await?;
//   let session_token = session.generate_access_token(&json_web_token_private_key, session.expiration_date).await?;
//   let update_access_policies_action = Action::get_by_name("accessPolicies.update", &test_environment.database_pool).await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: update_access_policies_action.id,
//     permission_level: PermissionLevel::None,
//     is_inheritance_enabled: true,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     scoped_resource_type: ResourceType::Server,
//     ..Default::default()
//   };
//   let access_policy = AccessPolicy::create(&access_policy_properties, &test_environment.database_pool).await?;

//   let response = test_server.patch(&format!("/access-policies/{}", access_policy.id))
//     .add_cookie(Cookie::new("session_access_token", format!("Bearer {}", session_token)))
//     .json(&serde_json::json!({
//       "permission_level": "User",
//       "is_inheritance_enabled": false
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

//   return Ok(());

// }

// /// Verifies that the router can return a 404 status code if the access policy does not exist.
// #[tokio::test]
// async fn verify_access_policy_exists_when_patching_access_policy() -> Result<(), TestSlashstepServerError> {

//   let test_environment = EndToEndTestEnvironment::new().await?;
//   initialize_required_tables(&test_environment.database_pool).await?;
//   initialize_predefined_actions(&test_environment.database_pool).await?;
//   initialize_predefined_roles(&test_environment.database_pool).await?;
//   initialize_predefined_groups(&test_environment.database_pool).await?;
//   initialize_predefined_configurations(&test_environment.database_pool).await?;
//   let state = AppState {
//     database_pool: test_environment.database_pool.clone(),
//   };

//   let router = super::get_router(state.clone())
//     .with_state(state)
//     .into_make_service_with_connect_info::<SocketAddr>();
//   let test_server = TestServer::new(router);

//   let response = test_server.patch(&format!("/access-policies/{}", Uuid::now_v7()))
//     .json(&serde_json::json!({
//       "permission_level": "User",
//       "is_inheritance_enabled": false
//     }))
//     .await;

//   assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

//   return Ok(());

// }
