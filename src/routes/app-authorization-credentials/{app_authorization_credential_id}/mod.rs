/*
 *
 * Any functionality for /app-authorization-credentials/{app_authorization_credential_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

use crate::utilities::route_handler_utilities::create_trace_layer_span;
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
        app_authorization_credential::AppAuthorizationCredential,
        http_transaction::HTTPTransaction,
        user::User,
    },
    routes::GetResourceResponseBody,
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_app_authorization_credential_by_id, get_principal_type_and_id_from_principal,
        get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
};
use reqwest::StatusCode;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

/// GET /app-authorization-credentials/{app_authorization_credential_id}
///
/// Gets an app authorization credential by its ID.
#[axum::debug_handler]
async fn handle_get_app_authorization_credential_request(
    Path(app_authorization_credential_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<AppAuthorizationCredential>>, HTTPError> {
    let app_authorization_credential_id = get_uuid_from_string(
        &app_authorization_credential_id,
        "app authorization credential",
    )
    .await?;
    let target_app_authorization_credential = get_app_authorization_credential_by_id(
        &app_authorization_credential_id,
        &state.database_pool,
    )
    .await?;
    let get_app_authorizations_action =
        get_action_by_name("appAuthorizationCredentials.get", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_app_authorizations_action.id,
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
        &ResourceType::AppAuthorizationCredential,
        Some(&target_app_authorization_credential.id),
        &get_app_authorizations_action,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_app_authorizations_action.id,
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
            target_resource_type: ResourceType::AppAuthorizationCredential,
            target_app_authorization_credential_id: Some(target_app_authorization_credential.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!(
        "Successfully returned app authorization credential {}.",
        target_app_authorization_credential.id
    );

    let response_body = GetResourceResponseBody {
        data: target_app_authorization_credential.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /app-authorization-credentials/{app_authorization_credential_id}
///
/// Deletes an app authorization credential by its ID.
#[axum::debug_handler]
async fn handle_delete_app_authorization_credential_request(
    Path(app_authorization_credential_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let app_authorization_credential_id = get_uuid_from_string(
        &app_authorization_credential_id,
        "app authorization credential",
    )
    .await?;
    let target_app_authorization_credential = get_app_authorization_credential_by_id(
        &app_authorization_credential_id,
        &state.database_pool,
    )
    .await?;
    let delete_app_authorization_credentials_action =
        get_action_by_name("appAuthorizationCredentials.delete", &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_app_authorization_credentials_action.id,
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
        &ResourceType::AppAuthorizationCredential,
        Some(&target_app_authorization_credential.id),
        &delete_app_authorization_credentials_action,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_app_authorization_credential
        .delete(&state.database_pool)
        .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete app authorization credential: {:?}",
            error
        )));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_app_authorization_credentials_action.id,
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
            target_resource_type: ResourceType::AppAuthorizationCredential,
            target_app_authorization_credential_id: Some(target_app_authorization_credential.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!(
        "Successfully deleted app authorization credential {}.",
        target_app_authorization_credential.id
    );
    Ok(StatusCode::NO_CONTENT)
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/app-authorization-credentials/{app_authorization_credential_id}",
            axum::routing::get(handle_get_app_authorization_credential_request),
        )
        .route(
            "/app-authorization-credentials/{app_authorization_credential_id}",
            axum::routing::delete(handle_delete_app_authorization_credential_request),
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
