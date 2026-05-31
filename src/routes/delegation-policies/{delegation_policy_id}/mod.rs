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
        delegation_policy::{DelegationPolicy, EditableDelegationPolicyProperties},
        http_transaction::HTTPTransaction,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_delegation_policy_by_id,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, is_authenticated_user_anonymous, verify_delegate_permissions,
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
 * Any functionality for /delegation-policies/{delegation_policy_id} should be handled here.
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
use tracing::{info, trace};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

/// GET /delegation-policies/{delegation_policy_id}
///
/// Gets an delegation_policy by its ID.
#[axum::debug_handler]
async fn handle_get_delegation_policy_request(
    Path(delegation_policy_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<DelegationPolicy>>, HTTPError> {
    let delegation_policy_id = get_uuid_from_string(
        &delegation_policy_id,
        "delegation policy",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_delegation_policy = get_delegation_policy_by_id(
        &delegation_policy_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let get_delegation_policies_action = get_action_by_name(
        "delegationPolicies.get",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_delegation_policies_action.id,
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
        &ResourceType::DelegationPolicy,
        Some(&target_delegation_policy.id),
        &get_delegation_policies_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_delegation_policies_action.id,
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
            target_resource_type: ResourceType::DelegationPolicy,
            target_delegation_policy_id: Some(target_delegation_policy.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!(
        "Successfully returned delegation policy {}.",
        target_delegation_policy.id
    );

    let response_body = GetResourceResponseBody {
        data: target_delegation_policy.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /delegation_policies/{delegation_policy_id}
///
/// Deletes a delegation policy by its ID.
#[axum::debug_handler]
async fn handle_delete_delegation_policy_request(
    Path(delegation_policy_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let delegation_policy_id = get_uuid_from_string(
        &delegation_policy_id,
        "delegation policy",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_delegation_policy = get_delegation_policy_by_id(
        &delegation_policy_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let delete_delegation_policies_action = get_action_by_name(
        "delegationPolicies.delete",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_delegation_policies_action.id,
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
        &ResourceType::DelegationPolicy,
        Some(&target_delegation_policy.id),
        &delete_delegation_policies_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_delegation_policy.delete(&state.database_pool).await {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete delegation policy: {:?}",
            error
        )));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_delegation_policies_action.id,
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
            target_resource_type: ResourceType::DelegationPolicy,
            target_delegation_policy_id: Some(target_delegation_policy.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!(
        "Successfully deleted delegation policy {}.",
        target_delegation_policy.id
    );
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /delegation_policies/{delegation_policy_id}
///
/// Updates a delegation policy by its ID.
#[axum::debug_handler]
async fn handle_patch_delegation_policy_request(
    Path(delegation_policy_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableDelegationPolicyProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<DelegationPolicy>>, HTTPError> {
    let updated_delegation_policy_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    let delegation_policy_id = get_uuid_from_string(
        &delegation_policy_id,
        "delegation policy",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let original_target_delegation_policy = get_delegation_policy_by_id(
        &delegation_policy_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let update_access_policy_action = get_action_by_name(
        "delegationPolicies.update",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
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
        &ResourceType::DelegationPolicy,
        Some(&original_target_delegation_policy.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!(
        "Updating delegation policy {}...",
        original_target_delegation_policy.id
    );
    let updated_target_delegation_policy = match original_target_delegation_policy
        .update(&updated_delegation_policy_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_delegation_policy) => updated_target_delegation_policy,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update delegation policy {}: {:?}",
                original_target_delegation_policy.id, error
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
            target_resource_type: ResourceType::DelegationPolicy,
            target_delegation_policy_id: Some(updated_target_delegation_policy.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!(
        "Successfully updated delegation policy {}.",
        updated_target_delegation_policy.id
    );

    let response_body = PatchResourceResponseBody {
        data: updated_target_delegation_policy,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/delegation-policies/{delegation_policy_id}",
            axum::routing::get(handle_get_delegation_policy_request),
        )
        .route(
            "/delegation-policies/{delegation_policy_id}",
            axum::routing::delete(handle_delete_delegation_policy_request),
        )
        .route(
            "/delegation-policies/{delegation_policy_id}",
            axum::routing::patch(handle_patch_delegation_policy_request),
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
