/**
 * 
 * Any functionality for /item-connections/{item_connection_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use crate::{
  AppState, 
  HTTPError, 
  middleware::{authentication_middleware, http_request_middleware}, 
  resources::{
    access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, item_connection::ItemConnection, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_all_resource_hierarchies, get_authenticated_principal, get_item_connection_by_id, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}
};

// #[path = "./access-policies/mod.rs"]
// mod access_policies;
#[cfg(test)]
mod tests;

/// GET /item-connections/{item_connection_id}
/// 
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_item_connection_request(
  Path(item_connection_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<Json<ItemConnection>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let item_connection_id = get_uuid_from_string(&item_connection_id, "item connection", &http_transaction, &state.database_pool).await?;
  let target_item_connection = get_item_connection_by_id(&item_connection_id, &http_transaction, &state.database_pool).await?;
  let get_item_connections_action = get_action_by_name("slashstep.itemConnections.get", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &get_item_connections_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;

  let resource_hierarchies = get_all_resource_hierarchies(&target_item_connection, &AccessPolicyResourceType::ItemConnection, &target_item_connection.id, &http_transaction, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  for index in 0..resource_hierarchies.len() {

    let resource_hierarchy = &resource_hierarchies[index];
    match verify_principal_permissions(&authenticated_principal, &get_item_connections_action, resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await {

      Ok(_) => break,

      Err(error) => {

        if index < resource_hierarchies.len() - 1 {

          continue;

        }

        return Err(error);

      }

    }

  }
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_item_connections_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::ItemConnection,
    target_item_connection_id: Some(target_item_connection.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully returned item connection {}.", target_item_connection.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok(Json(target_item_connection));

}

// /// DELETE /item-connections/{item_connection_id}
// /// 
// /// Deletes an app by its ID.
// #[axum::debug_handler]
// async fn handle_delete_app_request(
//   Path(item_connection_id): Path<String>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>,
//   Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
// ) -> Result<StatusCode, HTTPError> {

//   let item_connection_id = get_uuid_from_string(&item_connection_id, "app", &http_transaction, &state.database_pool).await?;
//   let response = delete_resource(
//     State(state), 
//     Extension(http_transaction), 
//     Extension(authenticated_user), 
//     Extension(authenticated_app), 
//     Extension(authenticated_app_authorization),
//     Some(&AccessPolicyResourceType::App),
//     &item_connection_id, 
//     "slashstep.apps.delete",
//     "app",
//     &ActionLogEntryTargetResourceType::App,
//     |item_connection_id, database_pool| Box::new(App::get_by_id(item_connection_id, database_pool))
//   ).await;

//   return response;

// }

// /// PATCH /item-connections/{item_connection_id}
// /// 
// /// Updates an app by its ID.
// #[axum::debug_handler]
// async fn handle_patch_app_request(
//   Path(item_connection_id): Path<String>,
//   State(state): State<AppState>, 
//   Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
//   Extension(authenticated_user): Extension<Option<Arc<User>>>,
//   Extension(authenticated_app): Extension<Option<Arc<App>>>,
//   Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
//   body: Result<Json<EditableAppProperties>, JsonRejection>
// ) -> Result<Json<App>, HTTPError> {

//   let http_transaction = http_transaction.clone();

//   ServerLogEntry::trace("Verifying request body...", Some(&http_transaction.id), &state.database_pool).await.ok();
//   let updated_app_properties = match body {

//     Ok(updated_app_properties) => updated_app_properties,

//     Err(error) => {

//       let http_error = match error {

//         JsonRejection::JsonDataError(error) => HTTPError::BadRequestError(Some(error.to_string())),

//         JsonRejection::JsonSyntaxError(_) => HTTPError::BadRequestError(Some(format!("Failed to parse request body. Ensure the request body is valid JSON."))),

//         JsonRejection::MissingJsonContentType(_) => HTTPError::BadRequestError(Some(format!("Missing request body content type. It should be \"application/json\"."))),

//         JsonRejection::BytesRejection(error) => HTTPError::InternalServerError(Some(format!("Failed to parse request body: {:?}", error))),

//         _ => HTTPError::InternalServerError(Some(error.to_string()))

//       };
      
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   };

//   let original_target_field = get_app_by_id(&item_connection_id, &http_transaction, &state.database_pool).await?;
//   let resource_hierarchy = get_resource_hierarchy(&original_target_field, &AccessPolicyResourceType::App, &original_target_field.id, &http_transaction, &state.database_pool).await?;
//   let update_access_policy_action = get_action_by_name("slashstep.apps.update", &http_transaction, &state.database_pool).await?;
//   verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &update_access_policy_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
//   let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
//   verify_principal_permissions(&authenticated_principal, &update_access_policy_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

//   ServerLogEntry::trace(&format!("Updating authenticated_app {}...", original_target_field.id), Some(&http_transaction.id), &state.database_pool).await.ok();
//   let updated_target_action = match original_target_field.update(&updated_app_properties, &state.database_pool).await {

//     Ok(updated_target_action) => updated_target_action,

//     Err(error) => {

//       let http_error = HTTPError::InternalServerError(Some(format!("Failed to update authenticated_app: {:?}", error)));
//       ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
//       return Err(http_error);

//     }

//   };

//   ActionLogEntry::create(&InitialActionLogEntryProperties {
//     action_id: update_access_policy_action.id,
//     http_transaction_id: Some(http_transaction.id),
//     actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
//     actor_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = &authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
//     actor_item_connection_id: if let AuthenticatedPrincipal::App(authenticated_app) = &authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
//     target_resource_type: ActionLogEntryTargetResourceType::Action,
//     target_action_id: Some(updated_target_action.id),
//     ..Default::default()
//   }, &state.database_pool).await.ok();
//   ServerLogEntry::success(&format!("Successfully updated action {}.", updated_target_action.id), Some(&http_transaction.id), &state.database_pool).await.ok();

//   return Ok(Json(updated_target_action));

// }

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/item-connections/{item_connection_id}", axum::routing::get(handle_get_item_connection_request))
    // .route("/item-connections/{item_connection_id}", axum::routing::delete(handle_delete_app_request))
    // .route("/item-connections/{item_connection_id}", axum::routing::patch(handle_patch_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}
