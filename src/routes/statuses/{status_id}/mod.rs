use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        status::{EditableStatusProperties, Status},
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_status_by_id, get_uuid_from_string, is_authenticated_user_anonymous,
        validate_field_length, validate_resource_name, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /statuses/{status_id} should be handled here.
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

/// GET /statuses/{status_id}
///
/// Gets a status by its ID.
#[axum::debug_handler]
async fn handle_get_status_request(
    Path(status_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<Status>>, HTTPError> {
    let status_id = get_uuid_from_string(
        &status_id,
        "status",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_status =
        get_status_by_id(&status_id, &http_transaction, &state.database_pool).await?;
    let get_statuses_action =
        get_action_by_name("statuses.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_statuses_action.id,
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
        &ResourceType::Status,
        Some(&target_status.id),
        &get_statuses_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_statuses_action.id,
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
            target_resource_type: ResourceType::Status,
            target_status_id: Some(target_status.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned status {}.", target_status.id);

    let response_body = GetResourceResponseBody {
        data: target_status.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /statuses/{status_id}
///
/// Deletes an status by its ID.
#[axum::debug_handler]
async fn handle_delete_status_request(
    Path(status_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let status_id = get_uuid_from_string(
        &status_id,
        "status",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_status =
        get_status_by_id(&status_id, &http_transaction, &state.database_pool).await?;
    let delete_statuses_action =
        get_action_by_name("statuses.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_statuses_action.id,
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
        &ResourceType::Status,
        Some(&target_status.id),
        &delete_statuses_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_status.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete status: {:?}", error)));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_statuses_action.id,
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
            target_resource_type: ResourceType::Status,
            target_status_id: Some(target_status.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted status {}.", target_status.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /statuses/{status_id}
///
/// Updates an status by its ID.
#[axum::debug_handler]
async fn handle_patch_status_request(
    Path(status_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableStatusProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<Status>>, HTTPError> {
    let status_id = get_uuid_from_string(
        &status_id,
        "status",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let updated_status_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(name) = &updated_status_properties.name {
        validate_field_length(
            name,
            "statuses.maximumNameLength",
            "name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
        validate_resource_name(
            name,
            "statuses.allowedNameRegex",
            "status",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(display_name) = &updated_status_properties.display_name {
        validate_field_length(
            display_name,
            "statuses.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    if let Some(Some(description)) = &updated_status_properties.description {
        validate_field_length(
            description,
            "statuses.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    let original_target_status =
        get_status_by_id(&status_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("statuses.update", &http_transaction, &state.database_pool).await?;
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
        &ResourceType::Status,
        Some(&original_target_status.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating status {}...", original_target_status.id);
    let updated_target_status = match original_target_status
        .update(&updated_status_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_status) => updated_target_status,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update status: {:?}",
                error
            )));
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
            target_resource_type: ResourceType::Status,
            target_status_id: Some(updated_target_status.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated status {}.", updated_target_status.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_status,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/statuses/{status_id}",
            axum::routing::get(handle_get_status_request),
        )
        .route(
            "/statuses/{status_id}",
            axum::routing::delete(handle_delete_status_request),
        )
        .route(
            "/statuses/{status_id}",
            axum::routing::patch(handle_patch_status_request),
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
}
