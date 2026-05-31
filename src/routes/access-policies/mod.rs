use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceError, ResourceType,
        access_policy::{
            AccessPolicy, AccessPolicyPrincipalType, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
            InitialAccessPolicyProperties, PermissionLevel,
        },
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{
        CreateResourceResponseBody, ListResourcesResponseBody, ResourceListQueryParameters,
        http_transactions::http_transaction_id,
    },
    utilities::route_handler_utilities::{
        get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        is_authenticated_user_anonymous, match_db_error, match_slashstepql_error,
        verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Query, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{info, info_span, trace, warn};
/*
 *
 * Any functionality for /access-policies should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2025 – 2026 Beastslash LLC
 *
 */
use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[path = "./{access_policy_id}/mod.rs"]
pub mod access_policy_id;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServerAccessPolicyRequestBody {
    pub action_id: Uuid,
    pub permission_level: PermissionLevel,
    pub is_inheritance_enabled: bool,
    pub principal_type: AccessPolicyPrincipalType,
    pub principal_user_id: Option<Uuid>,
    pub principal_group_id: Option<Uuid>,
    pub principal_role_id: Option<Uuid>,
    pub principal_app_id: Option<Uuid>,
}

/// GET /access-policies
///
/// Lists access policies.
#[axum::debug_handler]
async fn handle_list_access_policies_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<AccessPolicy>>), HTTPError> {
    let list_resources_action = get_action_by_name(
        "accessPolicies.list",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &list_resources_action.id,
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
        &ResourceType::Server,
        None,
        &list_resources_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_access_policies = match AccessPolicy::list(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(queried_access_policies) => queried_access_policies,

        Err(error) => {
            let http_error = match error {
                ResourceError::SlashstepQLError(error) => match_slashstepql_error(
                    &error,
                    &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
                    "access policy",
                ),

                ResourceError::PostgresError(error) => match_db_error(&error, "access policies"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list access policies: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting access policies...");
    let resource_count = match AccessPolicy::count(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(resource_count) => resource_count,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to count access policies: {:?}",
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
            action_id: list_resources_action.id,
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
            target_resource_type: ResourceType::Server,
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    let queried_access_policy_list_length = queried_access_policies.len();
    info!(
        "Successfully returned {} {}.",
        queried_access_policy_list_length,
        if queried_access_policy_list_length == 1 {
            "access policy"
        } else {
            "access policies"
        }
    );

    let response_body = ListResourcesResponseBody::<AccessPolicy> {
        data: queried_access_policies,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

/// POST /access-policies
///
/// Creates an access policy on the server level.
#[axum::debug_handler]
async fn handle_create_access_policy_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<CreateServerAccessPolicyRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateResourceResponseBody<AccessPolicy>>), HTTPError> {
    let create_server_access_policy_request_body =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;

    // Make sure the authenticated_user can create access policies for the target action log entry.
    let create_access_policies_action = get_action_by_name(
        "accessPolicies.create",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_access_policies_action.id,
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
        &ResourceType::Server,
        None,
        &create_access_policies_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Make sure the authenticated_user has at least editor access to the access policy's action.
    let access_policy_action = get_action_by_id(
        &create_server_access_policy_request_body.action_id,
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let minimum_permission_level =
        if create_server_access_policy_request_body.permission_level > PermissionLevel::Editor {
            create_server_access_policy_request_body.permission_level
        } else {
            PermissionLevel::Editor
        };
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &access_policy_action.id,
        &http_transaction.id,
        &minimum_permission_level,
        &state.database_pool,
    )
    .await?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::Server,
        None,
        &access_policy_action,
        &http_transaction,
        &minimum_permission_level,
        &state.database_pool,
    )
    .await?;

    // Create the access policy.
    trace!("Creating access policy for server...");
    let access_policy = match AccessPolicy::create(
        &InitialAccessPolicyProperties {
            action_id: create_server_access_policy_request_body.action_id,
            permission_level: create_server_access_policy_request_body.permission_level,
            is_inheritance_enabled: create_server_access_policy_request_body.is_inheritance_enabled,
            principal_type: create_server_access_policy_request_body.principal_type,
            principal_user_id: create_server_access_policy_request_body.principal_user_id,
            principal_group_id: create_server_access_policy_request_body.principal_group_id,
            principal_role_id: create_server_access_policy_request_body.principal_role_id,
            principal_app_id: create_server_access_policy_request_body.principal_app_id,
            scoped_resource_type: ResourceType::Server,
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    {
        Ok(access_policy) => access_policy,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create access policy: {:?}",
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
            action_id: create_access_policies_action.id,
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
            target_resource_type: ResourceType::AccessPolicy,
            target_access_policy_id: Some(access_policy.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully created access policy {}.", access_policy.id);

    let response_body = CreateResourceResponseBody {
        data: access_policy.clone(),
    };

    Ok((StatusCode::CREATED, Json(response_body)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/access-policies",
            axum::routing::get(handle_list_access_policies_request),
        )
        .route(
            "/access-policies",
            axum::routing::post(handle_create_access_policy_request),
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
        .merge(access_policy_id::get_router(state.clone()))
}
