use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::{App, EditableAppProperties},
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_app_by_id,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, is_authenticated_user_anonymous, validate_field_length,
        verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /apps/{app_id} should be handled here.
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
pub mod actions;
#[path = "./app-credentials/mod.rs"]
pub mod app_credentials;

/// GET /apps/{app_id}
///
/// Gets an app by its ID.
#[axum::debug_handler]
async fn handle_get_app_request(
    Path(app_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<App>>, HTTPError> {
    let app_id =
        get_uuid_from_string(&app_id, "app", &http_transaction, &state.database_pool).await?;
    let target_app = get_app_by_id(&app_id, &http_transaction, &state.database_pool).await?;
    let get_apps_action =
        get_action_by_name("apps.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_apps_action.id,
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
        &ResourceType::App,
        Some(&target_app.id),
        &get_apps_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_apps_action.id,
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
            target_resource_type: ResourceType::App,
            target_app_id: Some(target_app.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned authenticated_app {}.", target_app.id);

    let response_body = GetResourceResponseBody {
        data: target_app.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /apps/{app_id}
///
/// Deletes an app by its ID.
#[axum::debug_handler]
async fn handle_delete_app_request(
    Path(app_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let app_id =
        get_uuid_from_string(&app_id, "app", &http_transaction, &state.database_pool).await?;
    let target_app = get_app_by_id(&app_id, &http_transaction, &state.database_pool).await?;
    let delete_apps_action =
        get_action_by_name("apps.delete", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_apps_action.id,
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
        &ResourceType::App,
        Some(&target_app.id),
        &delete_apps_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_app.delete(&state.database_pool).await {
        let http_error =
            HTTPError::InternalServerError(Some(format!("Failed to delete app: {:?}", error)));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_apps_action.id,
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
            target_resource_type: ResourceType::App,
            target_app_id: Some(target_app.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted app {}.", target_app.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /apps/{app_id}
///
/// Updates an app by its ID.
#[axum::debug_handler]
async fn handle_patch_app_request(
    Path(app_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableAppProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<App>>, HTTPError> {
    let app_id =
        get_uuid_from_string(&app_id, "app", &http_transaction, &state.database_pool).await?;
    let updated_app_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(updated_app_name) = &updated_app_properties.name {
        validate_field_length(
            updated_app_name,
            "apps.maximumNameLength",
            "name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    };
    if let Some(updated_app_display_name) = &updated_app_properties.display_name {
        validate_field_length(
            updated_app_display_name,
            "apps.maximumDisplayNameLength",
            "display_name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    };

    let original_target_app =
        get_app_by_id(&app_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action =
        get_action_by_name("apps.update", &http_transaction, &state.database_pool).await?;
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
        &ResourceType::App,
        Some(&original_target_app.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating authenticated_app {}...", original_target_app.id);
    let updated_target_app = match original_target_app
        .update(&updated_app_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_app) => updated_target_app,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update authenticated_app: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: update_access_policy_action.id,
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
            target_resource_type: ResourceType::App,
            target_app_id: Some(updated_target_app.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated app {}.", updated_target_app.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_app,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/apps/{app_id}", axum::routing::get(handle_get_app_request))
        .route(
            "/apps/{app_id}",
            axum::routing::delete(handle_delete_app_request),
        )
        .route(
            "/apps/{app_id}",
            axum::routing::patch(handle_patch_app_request),
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
        .merge(actions::get_router(state.clone()))
        .merge(access_policies::get_router(state.clone()))
        .merge(app_credentials::get_router(state.clone()))
}
