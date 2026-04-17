/**
 * 
 * Any test cases for /projects/{project_id}/item-type-icons should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::{io::Cursor, net::SocketAddr};
use axum_extra::extract::cookie::Cookie;
use axum_test::{TestServer, multipart::{MultipartForm, Part}};
use image::{ImageBuffer, ImageFormat, RgbImage};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action::Action, item_type_icon::{DEFAULT_RESOURCE_LIST_LIMIT, ItemTypeIcon, ItemTypeIconParentResourceType}}, routes::ListResourcesResponseBody, tests::{TestEnvironment, TestSlashstepServerError}};

#[tokio::test]
async fn verify_successful_item_type_icon_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "itemTypeIcons.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_item_type_icons_action = Action::get_by_name("itemTypeIcons.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_project = test_environment.create_random_project().await?;
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };

  struct TestImageMetadata {
    file_extension: String,
    mime_type: String,
    image_format: Option<ImageFormat>
  }

  let test_image_metadata_list = vec![
    TestImageMetadata {
      file_extension: "png".to_string(),
      mime_type: "image/png".to_string(),
      image_format: Some(ImageFormat::Png)
    },
    TestImageMetadata {
      file_extension: "jpg".to_string(),
      mime_type: "image/jpeg".to_string(),
      image_format: Some(ImageFormat::Jpeg)
    },
    TestImageMetadata {
      file_extension: "svg".to_string(),
      mime_type: "image/svg+xml".to_string(),
      image_format: None
    }
  ];

  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  for test_image_metadata in test_image_metadata_list {

    let display_name = Uuid::now_v7().to_string();
    let display_name_part = Part::text(&display_name);
    let icon_data_part = match test_image_metadata.image_format {
      
      Some(image_format) => {
        
        let icon_data_buffer: RgbImage = ImageBuffer::new(16, 16);
        let mut icon_data_bytes = Vec::new();
        icon_data_buffer.write_to(&mut Cursor::new(&mut icon_data_bytes), image_format).unwrap();
        Part::bytes(icon_data_bytes)

      },

      None => {
        
        let svg_data = r##"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="#000000"/></svg>"##;
        Part::bytes(svg_data.as_bytes().to_vec())

      }
      
    }.file_name(format!("icon.{}", test_image_metadata.file_extension)).mime_type(&test_image_metadata.mime_type);
    let multipart_form = MultipartForm::new()
      .add_part("display_name", display_name_part)
      .add_part("icon_data", icon_data_part);

    let response = test_server.post(&format!("/projects/{}/item-type-icons", dummy_project.id))
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .multipart(multipart_form)
      .await;
    
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let response_item_type_icon: ItemTypeIcon = response.json();
    assert_eq!(response_item_type_icon.display_name, display_name);
    assert_eq!(response_item_type_icon.parent_resource_type, ItemTypeIconParentResourceType::Project);
    assert_eq!(response_item_type_icon.parent_project_id, Some(dummy_project.id));

  }

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_resource_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "itemTypeIcons.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_type_icons_action = Action::get_by_name("itemTypeIcons.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypeIcons.list" action.
  let list_item_type_icons_action = Action::get_by_name("itemTypeIcons.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_item_type_icon = test_environment.create_random_item_type_icon(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_type_icons: ListResourcesResponseBody::<ItemTypeIcon> = response.json();
  assert_eq!(response_item_type_icons.total_count, 1);
  assert_eq!(response_item_type_icons.resources.len(), 1);

  let query = format!("parent_project_id = {}", quote_literal(&dummy_project.id.to_string()));
  let actual_item_type_icon_count = ItemTypeIcon::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_type_icons.total_count, actual_item_type_icon_count);

  let actual_item_type_icons = ItemTypeIcon::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_type_icons.resources.len(), actual_item_type_icons.len());
  assert_eq!(response_item_type_icons.resources[0].id, actual_item_type_icons[0].id);
  assert_eq!(response_item_type_icons.resources[0].id, shown_item_type_icon.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_resource_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "itemTypeIcons.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_type_icons_action = Action::get_by_name("itemTypeIcons.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypeIcons.list" action.
  let list_item_type_icons_action = Action::get_by_name("itemTypeIcons.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  let shown_item_type_icon = test_environment.create_random_item_type_icon(Some(&dummy_project.id)).await?;

  // Set up the server and send the request.
  let additional_query = format!("id = '{}'", shown_item_type_icon.id);
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_item_type_icons: ListResourcesResponseBody::<ItemTypeIcon> = response.json();
  assert_eq!(response_item_type_icons.total_count, 1);
  assert_eq!(response_item_type_icons.resources.len(), 1);

  let query = format!("parent_project_id = {} AND ({})", quote_literal(&dummy_project.id.to_string()), additional_query);
  let actual_item_type_icon_count = ItemTypeIcon::count(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_type_icons.total_count, actual_item_type_icon_count);

  let actual_item_type_icons = ItemTypeIcon::list(&query, &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;
  assert_eq!(response_item_type_icons.resources.len(), actual_item_type_icons.len());
  assert_eq!(response_item_type_icons.resources[0].id, actual_item_type_icons[0].id);
  assert_eq!(response_item_type_icons.resources[0].id, shown_item_type_icon.id);

  return Ok(());

}

/// Verifies that the default access policy list limit is enforced.
#[tokio::test]
async fn verify_default_resource_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "itemTypeIcons.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_type_icons_action = Action::get_by_name("itemTypeIcons.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "itemTypeIcons.list" action.
  let list_item_type_icons_action = Action::get_by_name("itemTypeIcons.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_project = test_environment.create_random_project().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    test_environment.create_random_item_type_icon(Some(&dummy_project.id)).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<ItemTypeIcon> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_item_type_icon_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_type_icons_action = Action::get_by_name("itemTypeIcons.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_type_icons_action.id, &ActionPermissionLevel::User).await?;
  let list_item_type_icons_action = Action::get_by_name("itemTypeIcons.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_item_type_icons() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_item_type_icons_action = Action::get_by_name("itemTypeIcons.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  let list_item_type_icons_action = Action::get_by_name("itemTypeIcons.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_item_type_icons_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);

  let bad_requests = vec![
    test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM item_type_icons")),
    test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
      .add_query_param("query", format!("SELECT * FROM item_type_icons WHERE action_id = {}", get_item_type_icons_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
      .add_query_param("query", format!("action_ied = {}", get_item_type_icons_action.id)),
    test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
      .add_query_param("query", format!("1 = 1"))
  ];

  for request in unprocessable_entity_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  }

  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_listing_item_type_icons() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_item_type_icons() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Create a dummy action.
  let dummy_project = test_environment.create_random_project().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router);
  let response = test_server.get(&format!("/projects/{}/item-type-icons", &dummy_project.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}