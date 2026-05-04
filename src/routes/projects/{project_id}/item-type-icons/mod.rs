/**
 * 
 * Any functionality for /projects/{project_id}/item-type-icons should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::{io::Cursor, sync::Arc, vec};
use axum::{Extension, Json, Router, body::Bytes, extract::{Path, Query, State}};
use axum_typed_multipart::{BaseMultipart, FieldData, TryFromMultipart, TypedMultipartError};
use deadpool_postgres::Pool;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use svg_hush::data_url_filter;
use tokio::fs::create_dir_all;
use usvg::Tree;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, ResourceType, access_policy::{ActionPermissionLevel, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, configuration::Configuration, http_transaction::HTTPTransaction, item_type_icon::{InitialItemTypeIconProperties, ItemTypeIcon, ItemTypeIconParentResourceType}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_principal_type_and_id_from_principal, get_project_by_id, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, validate_field_length, verify_delegate_permissions, verify_principal_permissions}};

/// GET /projects/{project_id}/item-type-icons
/// 
/// Lists item type icons for a project.
#[axum::debug_handler]
async fn handle_list_item_type_icons_request(
  Path(project_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<ItemTypeIcon>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("itemTypeIcons.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_project_id = {}{}", 
    quote_literal(&project_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND ({})", query))).unwrap_or("".to_string())
  );
  let queried_resources = match ItemTypeIcon::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "item type icons"),

        ResourceError::PostgresError(error) => match_db_error(&error, "item type icons"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list item type icons: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting item type icons..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match ItemTypeIcon::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count item type icons: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Project,
    target_project_id: Some(target_project.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "item type icon" } else { "item type icons" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<ItemTypeIcon> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

#[derive(Debug, TryFromMultipart)]
pub struct CreateItemTypeIconRequestData {
  pub display_name: String,
  #[form_data(limit = "1MB")]
  pub icon_data: FieldData<Bytes>
}

impl From<TypedMultipartError> for HTTPError {

  fn from(error: TypedMultipartError) -> Self {

    match error {

      TypedMultipartError::FieldTooLarge { field_name, limit_bytes } => HTTPError::PayloadTooLarge(Some(format!("The file provided for {} exceeds the maximum allowed size of {} bytes.", field_name, limit_bytes))),

      TypedMultipartError::InvalidRequest { source: _ } => HTTPError::BadRequest(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

      TypedMultipartError::InvalidRequestBody { source: _ } => HTTPError::BadRequest(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

      TypedMultipartError::DuplicateField { field_name } => HTTPError::BadRequest(Some(format!("The \"{}\" field is duplicated. There should only be one.", field_name))),

      TypedMultipartError::MissingField { field_name } => HTTPError::BadRequest(Some(format!("The \"{}\" field is required. Provide it, then try again.", field_name))),

      TypedMultipartError::NamelessField => HTTPError::BadRequest(Some(format!("One of the fields in the multipart form data is missing a name. Ensure all fields have names, then try again."))),

      TypedMultipartError::WrongFieldType { field_name, wanted_type, source: _ } => HTTPError::BadRequest(Some(format!("The field \"{}\" must be of type {}.", field_name, wanted_type))),

      _ => HTTPError::InternalServerError(Some(format!("Failed to parse multipart form data: {:?}", error)))

    }

  }

}

/// POST /projects/{project_id}/item-type-icons
/// 
/// Creates a item type icon for a project.
#[axum::debug_handler]
async fn handle_create_item_type_icon_request(
  Path(project_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<BaseMultipart<CreateItemTypeIconRequestData, HTTPError>, HTTPError>
) -> Result<(StatusCode, Json<ItemTypeIcon>), HTTPError> {

  /// Validates the provided content type is an allowed content type for item type icon icons.
  async fn validate_content_type(content_type: &str, http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<(), HTTPError> {

    ServerLogEntry::trace(&format!("Validating content type {}...", content_type), Some(&http_transaction.id), &database_pool).await.ok();

    let allowed_content_types = vec![
      "image/png",
      "image/jpeg",
      "image/gif",
      "image/svg+xml"
    ];

    if !allowed_content_types.contains(&content_type) {

      let http_error = HTTPError::UnsupportedMediaType(Some(format!("The content type of the file provided in the \"icon_data\" field must be one of the following: {}.", allowed_content_types.join(", "))));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    return Ok(());

  }

  async fn verify_content_type_matches_contents(content_type: &str, contents: &Bytes, http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<(), HTTPError> {

    ServerLogEntry::trace(&format!("Verifying content type {} matches file contents...", content_type), Some(&http_transaction.id), &database_pool).await.ok();

    let kind = infer::get(contents);
    let actual_mime_type = kind.and_then(|kind| Some(kind.mime_type())).unwrap_or("unknown");
    if actual_mime_type != content_type && !(content_type == "image/svg+xml" && Tree::from_data(contents, &usvg::Options::default()).is_ok()) {

      let http_error = HTTPError::UnsupportedMediaType(Some(format!("The file provided in the \"icon_data\" field must match the expected format for {}. The content type provided was {}.", content_type, actual_mime_type)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    return Ok(());

  }

  async fn sanitize_contents(content_type: &str, contents: &Bytes, http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<Vec<u8>, HTTPError> {

    ServerLogEntry::trace(&format!("Sanitizing contents for content type {}...", content_type), Some(&http_transaction.id), &database_pool).await.ok();

    if content_type == "image/svg+xml" {

      let svg_string = match String::from_utf8(contents.to_vec()) {

        Ok(svg_string) => svg_string,

        Err(_) => {

          let http_error = HTTPError::BadRequest(Some(format!("The SVG file provided in the \"icon_data\" field is not valid UTF-8.")));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
          return Err(http_error);

        }

      };

      let svg_filter_result;
      let mut cleaned_bytes = Vec::new();
      {
        let mut svg_filter = svg_hush::Filter::new();
        svg_filter.set_data_url_filter(data_url_filter::allow_standard_images);
        svg_filter_result = svg_filter.filter(&mut svg_string.as_bytes(), &mut cleaned_bytes)
      }
      
      if svg_filter_result.is_err() {

        let http_error = HTTPError::BadRequest(Some(format!("The SVG file could not be parsed.")));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

      return Ok(cleaned_bytes);
      
    } else if content_type.starts_with("image/") {

      // For raster images, we can re-encode the image to ensure it's valid and doesn't contain any malicious content.
      let image = match image::load_from_memory(contents) {

        Ok(image) => image,

        Err(error) => {

          let http_error = HTTPError::BadRequest(Some(format!("The file provided in the \"icon_data\" field is not a valid image: {:?}", error)));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
          return Err(http_error);

        }

      };

      let mut cleaned_bytes = Vec::new();
      let image_format = match content_type {

        "image/png" => image::ImageFormat::Png,

        "image/jpeg" => image::ImageFormat::Jpeg,

        "image/gif" => image::ImageFormat::Gif,

        _ => {

          let http_error = HTTPError::UnsupportedMediaType(Some(format!("Unsupported content type: {}.", content_type)));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
          return Err(http_error);

        }

      };
      if let Err(error) = image.write_to(&mut Cursor::new(&mut cleaned_bytes), image_format) {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to re-encode the provided image: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

      return Ok(cleaned_bytes);

    }

    let http_error = HTTPError::UnsupportedMediaType(Some(format!("Unsupported content type: {}.", content_type)));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
    return Err(http_error);

  }

  async fn get_file_extension_from_content_type(content_type: &str, http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<String, HTTPError> {

    let file_extension = match content_type {

      "image/png" => "png",

      "image/jpeg" => "jpg",

      "image/gif" => "gif",

      "image/svg+xml" => "svg",

      _ => {

        let http_error = HTTPError::UnsupportedMediaType(Some(format!("Unsupported content type: {}.", content_type)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };

    return Ok(file_extension.to_string());

  }

  async fn get_item_type_icon_storage_directory_path(http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<String, HTTPError> {

    ServerLogEntry::trace(&format!("Getting configuration to know where to store item type icons..."), Some(&http_transaction.id), &database_pool).await.ok();
    let item_type_icon_storage_directory_path_configuration = match Configuration::get_by_name("itemTypeIcons.storageDirectoryPath", &database_pool).await {

      Ok(configuration) => configuration,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to get configuration for item type icon storage directory: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };

    let item_type_icon_storage_directory_path = match item_type_icon_storage_directory_path_configuration.text_value.or(item_type_icon_storage_directory_path_configuration.default_text_value) {

      Some(storage_directory_path) => storage_directory_path,

      None => {

        let http_error = HTTPError::InternalServerError(Some(format!("The configuration for the item type icon storage directory does not have a value.")));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };

    return Ok(item_type_icon_storage_directory_path);

  }

  async fn save_icon_file(file_path: &str, contents: &[u8], http_transaction: &HTTPTransaction, database_pool: &Pool) -> Result<(), HTTPError> {

    ServerLogEntry::trace(&format!("Saving item type icon file to {}...", file_path), Some(&http_transaction.id), &database_pool).await.ok();

    let mut directory_path_list = file_path.split("/").collect::<Vec<&str>>();
    directory_path_list.pop();
    let directory_path = directory_path_list.join("/");
    if let Err(error) = create_dir_all(&directory_path).await {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create directory for item type icon file: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    if let Err(error) = tokio::fs::write(file_path, contents).await {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to save item type icon file: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    return Ok(());

  }

  let body = match body {

    Ok(body) => body,

    Err(http_error) => {

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let project_id = get_uuid_from_string(&project_id, "project", &http_transaction, &state.database_pool).await?;
  let content_type = match &body.icon_data.metadata.content_type {

    Some(content_type) => content_type,

    None => {

      let http_error = HTTPError::BadRequest(Some(format!("The field \"icon_data\" must have a content type.")));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  validate_content_type(&content_type, &http_transaction, &state.database_pool).await?;
  verify_content_type_matches_contents(&content_type, &body.icon_data.contents, &http_transaction, &state.database_pool).await?;
  let cleaned_contents = sanitize_contents(&content_type, &body.icon_data.contents, &http_transaction, &state.database_pool).await?;
  validate_field_length(&body.display_name, "itemTypeIcons.maximumDisplayNameLength", "display_name", &http_transaction, &state.database_pool).await?;

  // Make sure the user can create item type icons for the target action.
  let target_project = get_project_by_id(&project_id, &http_transaction, &state.database_pool).await?;
  let create_item_type_icons_action = get_action_by_name("itemTypeIcons.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_item_type_icons_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Project, Some(&target_project.id), &create_item_type_icons_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Save the icon file to disk.
  // TODO: Support storing item type icons in cloud storage instead of on the local filesystem.
  let item_type_icon_id = Uuid::now_v7();
  let file_extension = get_file_extension_from_content_type(&content_type, &http_transaction, &state.database_pool).await?;
  let item_type_icon_storage_directory_path = get_item_type_icon_storage_directory_path(&http_transaction, &state.database_pool).await?;
  let item_type_icon_file_path = format!("{}/{}.{}", item_type_icon_storage_directory_path, item_type_icon_id, file_extension);
  save_icon_file(&item_type_icon_file_path, &cleaned_contents, &http_transaction, &state.database_pool).await?;

  // Create the item type icon.
  ServerLogEntry::trace(&format!("Creating item type icon for project {}...", project_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let item_type_icon = match ItemTypeIcon::create(&InitialItemTypeIconProperties {
    id: Some(item_type_icon_id),
    display_name: body.display_name.clone(),
    parent_resource_type: ItemTypeIconParentResourceType::Project,
    parent_project_id: Some(project_id)
  }, &state.database_pool).await {

    Ok(item_type_icon) => item_type_icon,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create item type icon: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  // Log the creation of the item type icon.
  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_item_type_icons_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::ItemTypeIcon,
    target_item_type_icon_id: Some(item_type_icon.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully created item type icon {}.", item_type_icon.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(item_type_icon)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/projects/{project_id}/item-type-icons", axum::routing::get(handle_list_item_type_icons_request))
    .route("/projects/{project_id}/item-type-icons", axum::routing::post(handle_create_item_type_icon_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
