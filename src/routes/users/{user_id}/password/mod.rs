use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use rust_decimal::{Decimal, prelude::ToPrimitive};
use serde::Deserialize;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, ResourceType, access_policy::{AccessPolicyPrincipalType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::{EditableUserProperties, User}}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_configuration_by_name, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_user_by_id, get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions, verify_principal_permissions}};

#[derive(Debug, Deserialize)]
pub struct UpdateUserPasswordRequestBody {

  /// The user's new password.
  pub new_password: String,

  /// The user's current password.
  /// 
  /// Required if `should_bypass_password_validation` is false and a password reset token is not provided.
  pub current_password: Option<String>,

  /// A password reset token that was previously generated for the user.
  ///
  /// Required if `should_bypass_password_validation` is false and the user's current password is not provided.
  pub password_reset_token: Option<String>,

  /// Whether to bypass validating the user's current password.
  /// 
  /// This is only respected if the authenticated principal has the `users.bypassPasswordValidation` permission.
  pub should_bypass_password_validation: bool,

  /// Whether to log the user out of all sessions after updating their password.
  /// 
  /// If true, all of the user's sessions will be deleted after their password is updated, except for the current session. This is useful in case the user's account was compromised and the user wants to quickly log out of all other sessions after updating their password.
  pub should_delete_other_sessions: bool,

  /// Whether to require the user to change their password on their next login.
  /// 
  /// If true, the user will be prevented from creating a new session until they change their password. This is useful for forcing a user to change their password after an administrator has updated it for them.
  pub should_require_password_change_on_next_login: bool,

}

/// PUT /users/{user_id}/password
/// 
/// Update a user's password.
/// 
/// ### Required permissions
/// | Action | Minimum permission level | Target resource |
/// | :- | :- | :- |
/// | `users.updatePassword` | User | The user specified by `{user_id}` |
/// | `users.bypassPasswordValidation` | User if `should_bypass_password_validation` is true, otherwise not required | The user specified by `{user_id}` |
#[axum::debug_handler]
async fn handle_update_user_password_request(
  Path(user_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<UpdateUserPasswordRequestBody>, JsonRejection>
) -> Result<(StatusCode, Json<User>), HTTPError> {

  async fn verify_principal_can_change_password(
    update_user_password_request_body: &UpdateUserPasswordRequestBody,
    authenticated_app_authorization_id: Option<&Uuid>,
    http_transaction: &HTTPTransaction,
    database_pool: &deadpool_postgres::Pool,
    principal_type: &AccessPolicyPrincipalType,
    principal_id: &Uuid,
    is_authenticated_user_anonymous: bool,
    target_user: &User
  ) -> Result<(), HTTPError> {

    if update_user_password_request_body.should_bypass_password_validation {

      let bypass_password_validation_action = get_action_by_name("users.bypassPasswordValidation", &http_transaction, &database_pool).await?;
      verify_delegate_permissions(authenticated_app_authorization_id, &bypass_password_validation_action.id, &http_transaction.id, &ActionPermissionLevel::User, &database_pool).await?;
      verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous, &ResourceType::User, Some(&target_user.id), &bypass_password_validation_action, &http_transaction, &ActionPermissionLevel::User, &database_pool).await?;

    } else if let Some(password_reset_token) = &update_user_password_request_body.password_reset_token {



    } else if let Some(current_password) = &update_user_password_request_body.current_password {

      if let Err(error) = target_user.verify_password(current_password.as_str()) {

        let http_error = match error {

          ResourceError::Argon2PasswordHashError(error) => match error {

            argon2::password_hash::Error::Password => HTTPError::Unauthorized(Some("The provided current password is incorrect. Check the password and try again.".to_string())),

            _ => HTTPError::InternalServerError(Some(format!("Failed to verify user's current password: {:?}", error))),

          }

          _ => HTTPError::InternalServerError(Some(format!("Failed to verify user's current password: {:?}", error))),

        };

        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    } else {

      let http_error = HTTPError::BadRequest(Some("Either current_password or password_reset_token must be provided in the request body, unless should_bypass_password_validation is true.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    return Ok(());

  }

  async fn verify_password_meets_requirements(password: &str, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool) -> Result<(), HTTPError> {

    let minimum_password_length_configuration = get_configuration_by_name("users.minimumPasswordLength", http_transaction, database_pool).await?;
    let minimum_password_length = match minimum_password_length_configuration.number_value.unwrap_or(minimum_password_length_configuration.default_number_value.unwrap_or(Decimal::from(0))).to_usize() {

      Some(minimum_password_length) => minimum_password_length,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Invalid minimum password length configuration value.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), database_pool).await.ok();
        return Err(http_error);

      }

    };
    if password.len() < minimum_password_length {

      let http_error = HTTPError::UnprocessableEntity(Some(format!("The new password must be at least {} characters long.", minimum_password_length)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    let maximum_password_length_configuration = get_configuration_by_name("users.maximumPasswordLength", &http_transaction, &database_pool).await?;
    let maximum_password_length = match maximum_password_length_configuration.number_value
      .unwrap_or(maximum_password_length_configuration.default_number_value
        .unwrap_or(Decimal::from(usize::MAX))
      ).to_usize() 
    {

      Some(maximum_password_length) => maximum_password_length,

      None => {

        let http_error = HTTPError::InternalServerError(Some("Invalid maximum password length configuration value.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };
    if password.len() > maximum_password_length {

      let http_error = HTTPError::UnprocessableEntity(Some(format!("The new password must be at most {} characters long.", maximum_password_length)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
      return Err(http_error);

    }

    return Ok(());

  }

  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  let user_id = get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
  let update_user_password_request_body = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
  verify_password_meets_requirements(&update_user_password_request_body.new_password, &http_transaction, &state.database_pool).await?;
  let authenticated_app_authorization_id = authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id);
  verify_principal_can_change_password(
    &update_user_password_request_body,
    authenticated_app_authorization_id,
    &http_transaction,
    &state.database_pool,
    &principal_type,
    &principal_id,
    is_authenticated_user_anonymous(authenticated_user.as_ref()),
    &target_user
  ).await?;

  let update_user_password_action = get_action_by_name("users.updatePassword", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization_id, &update_user_password_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::User, Some(&target_user.id), &update_user_password_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
  
  let hashed_password = match User::hash_password(&update_user_password_request_body.new_password) {

    Ok(hashed_password) => hashed_password,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to hash new password: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let updated_user = match target_user.update(&EditableUserProperties {
    hashed_password: Some(Some(hashed_password)),
    ..Default::default()
  }, &state.database_pool).await {

    Ok(updated_user) => updated_user,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete user: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: update_user_password_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::User,
    target_user_id: Some(target_user.id),
    ..Default::default()
  }, &state.database_pool).await.ok();

  ServerLogEntry::success(&format!("Successfully updated user {}'s password.", target_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();
  return Ok((StatusCode::OK, Json(updated_user)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/users/{user_id}/password", axum::routing::put(handle_update_user_password_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
