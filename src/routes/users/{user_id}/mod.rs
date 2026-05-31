use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceError, ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        user::{EditableUserProperties, EditableUserPropertiesRequestBody, User},
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_user_by_id, get_uuid_from_string, is_authenticated_user_anonymous,
        validate_field_length, validate_resource_name, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use postgres::error::SqlState;
use reqwest::StatusCode;
/*
 *
 * Any functionality for /users/{user_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{trace, info};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;
#[path = "./oauth-authorizations/mod.rs"]
pub mod oauth_authorizations;
pub mod password;
pub mod sessions;

/// GET /users/{user_id}
///
/// Gets a user by its ID.
#[axum::debug_handler]
async fn handle_get_user_request(
    Path(user_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<User>>, HTTPError> {
    let user_id =
        get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
    let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
    let get_users_action =
        get_action_by_name("users.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_users_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::User,
        Some(&target_user.id),
        &get_users_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_users_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::User,
            target_user_id: Some(target_user.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned user {}.", target_user.id);

    let response_body = GetResourceResponseBody {
        data: target_user.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /users/{user_id}
///
/// Deletes an user by its ID.
#[axum::debug_handler]
async fn handle_delete_user_request(
    Path(user_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let user_id =
        get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
    let target_user = get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
    let delete_users_action =
        get_action_by_name("users.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_users_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::User,
        Some(&target_user.id),
        &delete_users_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_user.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete user: {:?}", error)));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_users_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            reason: None, // TODO: Support reasons.
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::User,
            target_user_id: Some(target_user.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted user {}.", target_user.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /users/{user_id}
///
/// Updates an user by its ID.
#[axum::debug_handler]
async fn handle_patch_user_request(
    Path(user_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableUserPropertiesRequestBody>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<User>>, HTTPError> {
    let user_id =
        get_uuid_from_string(&user_id, "user", &http_transaction, &state.database_pool).await?;
    let updated_user_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(Some(username)) = &updated_user_properties.username {
        validate_field_length(
            username,
            "users.maximumNameLength",
            "username",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            username,
            "users.allowedNameRegex",
            "user",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(Some(display_name)) = &updated_user_properties.display_name {
        validate_field_length(
            display_name,
            "users.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    let original_target_user =
        get_user_by_id(&user_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("users.update", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &update_access_policy_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::User,
        Some(&original_target_user.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating user {}...", original_target_user.id);
    let updated_target_user = match original_target_user
        .update(
            &EditableUserProperties {
                username: updated_user_properties.username.clone(),
                display_name: updated_user_properties.display_name.clone(),
                hashed_password: None,
            },
            &state.database_pool,
        )
        .await
    {
        Ok(updated_target_user) => updated_target_user,

        Err(error) => {
            let http_error = match &error {
                ResourceError::PostgresError(error) => match error.as_db_error() {
                    Some(error) => {
                        if error.code() == &SqlState::CHECK_VIOLATION
                            && error.constraint() == Some("username_existence_check")
                        {
                            let message = if original_target_user.is_anonymous {
                                "Anonymous users cannot have usernames."
                            } else {
                                "Non-anonymous users must have usernames."
                            };
                            Some(HTTPError::UnprocessableEntity(Some(message.to_string())))
                        } else {
                            None
                        }
                    }

                    None => None,
                },

                _ => None,
            }
            .unwrap_or(HTTPError::InternalServerError(Some(format!(
                "Failed to update user: {:?}",
                error
            ))));
            http_error.log();
            return Err(http_error);
        }
    };

    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: update_access_policy_action.id,
            http_transaction_id: Some(http_transaction.id),
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::User,
            target_user_id: Some(updated_target_user.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated user {}.", updated_target_user.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_user,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/users/{user_id}",
            axum::routing::get(handle_get_user_request),
        )
        .route(
            "/users/{user_id}",
            axum::routing::delete(handle_delete_user_request),
        )
        .route(
            "/users/{user_id}",
            axum::routing::patch(handle_patch_user_request),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware::verify_absolute_maximum_rate_limits,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_user,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_app,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http_transaction_middleware::create_http_transaction,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(create_trace_layer_span))
        .merge(access_policies::get_router(state.clone()))
        .merge(oauth_authorizations::get_router(state.clone()))
        .merge(password::get_router(state.clone()))
        .merge(sessions::get_router(state.clone()))
}
