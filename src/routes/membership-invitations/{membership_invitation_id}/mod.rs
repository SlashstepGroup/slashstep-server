/*
 *
 * Any functionality for /membership-invitations/{membership_invitation_id} should be handled here.
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
        http_transaction::HTTPTransaction,
        membership_invitation::MembershipInvitation,
        user::User,
    },
    routes::GetResourceResponseBody,
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_membership_invitation_by_id, get_principal_type_and_id_from_principal,
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

/// GET /membership-invitations/{membership_invitation_id}
///
/// Gets a membership invitation by its ID.
#[axum::debug_handler]
async fn handle_get_membership_invitation_request(
    Path(membership_invitation_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<MembershipInvitation>>, HTTPError> {
    let membership_invitation_id = get_uuid_from_string(
        &membership_invitation_id,
        "membership invitation",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_membership_invitation = get_membership_invitation_by_id(
        &membership_invitation_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let get_membership_invitations_action = get_action_by_name(
        "membershipInvitations.get",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_membership_invitations_action.id,
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
        &ResourceType::MembershipInvitation,
        Some(&target_membership_invitation.id),
        &get_membership_invitations_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_membership_invitations_action.id,
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
            target_resource_type: ResourceType::MembershipInvitation,
            target_membership_invitation_id: Some(target_membership_invitation.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!(
        "Successfully returned membership invitation {}.",
        target_membership_invitation.id
    );

    let response_body = GetResourceResponseBody {
        data: target_membership_invitation.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /membership-invitations/{membership_invitation_id}
///
/// Deletes an membership invitation by its ID.
#[axum::debug_handler]
async fn handle_delete_membership_invitation_request(
    Path(membership_invitation_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let membership_invitation_id = get_uuid_from_string(
        &membership_invitation_id,
        "membership invitation",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_membership_invitation = get_membership_invitation_by_id(
        &membership_invitation_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let delete_membership_invitations_action = get_action_by_name(
        "membershipInvitations.delete",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_membership_invitations_action.id,
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
        &ResourceType::MembershipInvitation,
        Some(&target_membership_invitation.id),
        &delete_membership_invitations_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_membership_invitation
        .delete(&state.database_pool)
        .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete membership invitation: {:?}",
            error
        )));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_membership_invitations_action.id,
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
            target_resource_type: ResourceType::MembershipInvitation,
            target_membership_invitation_id: Some(target_membership_invitation.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!(
        "Successfully deleted membership invitation {}.",
        target_membership_invitation.id
    );
    Ok(StatusCode::NO_CONTENT)
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/membership-invitations/{membership_invitation_id}",
            axum::routing::get(handle_get_membership_invitation_request),
        )
        .route(
            "/membership-invitations/{membership_invitation_id}",
            axum::routing::delete(handle_delete_membership_invitation_request),
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
