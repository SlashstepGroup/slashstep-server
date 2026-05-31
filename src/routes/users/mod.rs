/*
 *
 * Any functionality for /users should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{user_id}/mod.rs"]
pub mod user_id;

use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::trace;

use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceError, ResourceType,
        access_policy::{
            AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties, PermissionLevel,
        },
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        group::{Group, GroupParentResourceType, PredefinedGroupType},
        http_transaction::HTTPTransaction,
        membership::{
            InitialMembershipProperties, Membership, MembershipParentResourceType,
            MembershipPrincipalType,
        },
        role::{InitialRoleProperties, PredefinedRoleType, Role, RoleParentResourceType},
        server_log_entry::ServerLogEntry,
        user::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialUserProperties, User},
    },
    routes::{CreateResourceResponseBody, ListResourcesResponseBody, ResourceListQueryParameters},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        is_authenticated_user_anonymous, match_db_error, match_slashstepql_error,
        validate_field_length, validate_resource_name, verify_delegate_permissions,
        verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Query, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequestBody {
    /// The username of the user.
    pub username: String,

    /// The display name of the user.
    pub display_name: Option<String>,

    /// The password of the user.
    pub password: String,
}

/// GET /users
///
/// Lists users.
#[axum::debug_handler]
async fn handle_list_users_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<User>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action =
        get_action_by_name("users.list", &http_transaction, &state.database_pool).await?;
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

    trace!("Listing users...");
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_resources = match User::list(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(queried_resources) => queried_resources,

        Err(error) => {
            let http_error = match error {
                ResourceError::SlashstepQLError(error) => {
                    match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "users")
                }

                ResourceError::PostgresError(error) => match_db_error(&error, "users"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list users: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting users...");
    let resource_count = match User::count(
        &query,
        &state.database_pool,
        Some(&principal_type),
        Some(&principal_id),
    )
    .await
    {
        Ok(resource_count) => resource_count,

        Err(error) => {
            let http_error =
                HTTPError::InternalServerError(Some(format!("Failed to count users: {:?}", error)));
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

    let queried_user_list_length = queried_resources.len();
    ServerLogEntry::success(
        &format!(
            "Successfully returned {} {}.",
            queried_user_list_length,
            if queried_user_list_length == 1 {
                "user"
            } else {
                "users"
            }
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = ListResourcesResponseBody::<User> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

/// POST /users
///
/// Creates a registered user on the server level.
#[axum::debug_handler]
async fn handle_create_user_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<CreateUserRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateResourceResponseBody<User>>), HTTPError> {
    let create_user_request_body =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    validate_resource_name(
        &create_user_request_body.username,
        "users.allowedNameRegex",
        "user",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_user_request_body.username,
        "users.maximumNameLength",
        "username",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_user_request_body.password,
        "users.maximumPasswordLength",
        "password",
        &http_transaction,
        &state.database_pool,
    )
    .await?;

    if let Some(display_name) = &create_user_request_body.display_name {
        validate_field_length(
            display_name,
            "users.maximumDisplayNameLength",
            "display name",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    // Make sure the authenticated_user can create apps for the target action log entry.
    let create_users_action =
        get_action_by_name("users.create", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_users_action.id,
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
        &create_users_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Hash the password.
    let hashed_password = match User::hash_password(&create_user_request_body.password) {
        Ok(hashed_password) => hashed_password,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to hash password: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    // Create the user.
    trace!("Creating user...");
    let user = match User::create(
        &InitialUserProperties {
            username: Some(create_user_request_body.username.clone()),
            display_name: create_user_request_body.display_name.clone(),
            hashed_password: Some(hashed_password),
            is_anonymous: false,
            ip_address: None,
        },
        &state.database_pool,
    )
    .await
    {
        Ok(user) => user,

        Err(error) => {
            let http_error = match error {
                ResourceError::ConflictError(_) => HTTPError::ConflictError(Some(
                    "A user with the same username already exists.".to_string(),
                )),
                error => HTTPError::InternalServerError(Some(format!(
                    "Failed to create user: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: create_users_action.id,
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
            target_user_id: Some(user.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    trace!("Getting registered users group...");

    let registered_users_group = match Group::get_protected_group_by_type(
        &GroupParentResourceType::Server,
        None,
        &PredefinedGroupType::RegisteredUsers,
        &state.database_pool,
    )
    .await
    {
        Ok(group) => group,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to get registered users group: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Creating membership for user in registered users group...");

    if let Err(error) = Membership::create(
        &InitialMembershipProperties {
            parent_resource_type: MembershipParentResourceType::Group,
            parent_group_id: Some(registered_users_group.id),
            parent_role_id: None,
            principal_user_id: Some(user.id),
            principal_app_id: None,
            principal_group_id: None,
            principal_type: MembershipPrincipalType::User,
        },
        &state.database_pool,
    )
    .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to create membership for user {} in registered users group: {:?}",
            user.id, error
        )));
        http_error.log();
        return Err(http_error);
    }

    trace!("Creating user account owners role for user...");

    let user_account_owners_role = match Role::create(&InitialRoleProperties {
    name: "user-account-owners".to_string(),
    display_name: "User account owners".to_string(),
    description: Some("Principals who own user accounts. Typically only one person has this role on a user.".to_string()),
    parent_resource_type: RoleParentResourceType::User,
    parent_group_id: None,
    parent_project_id: None,
    parent_user_id: Some(user.id),
    parent_workspace_id: None,
    parent_app_id: None,
    predefined_role_type: Some(PredefinedRoleType::UserAccountOwners)
  }, &state.database_pool).await {

    Ok(role) => role,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create account owners role for user {}: {:?}", user.id, error)));
      http_error.log();
      return Err(http_error);

    }

  };

    trace!("Creating access policies for user account owners role...");

    let allowed_actions = vec![
        "accessPolicies.create",
        "accessPolicies.get",
        "accessPolicies.list",
        "accessPolicies.update",
        "accessPolicies.delete",
        "actionLogEntries.get",
        "actionLogEntries.list",
        "delegationPolicies.get",
        "delegationPolicies.list",
        "delegationPolicies.create",
        "delegationPolicies.update",
        "delegationPolicies.delete",
        "sessionCredentials.create",
        "sessionCredentials.get",
        "sessionCredentials.list",
        "sessionCredentials.delete",
        "sessions.get",
        "sessions.list",
        "sessions.delete",
        "users.get",
        "users.list",
        "users.update",
        "users.delete",
    ];

    for action_name in allowed_actions {
        let action =
            get_action_by_name(action_name, &http_transaction, &state.database_pool).await?;

        ServerLogEntry::trace(
            &format!(
                "Creating access policy for action {} in user account owners role...",
                action_name
            ),
            Some(&http_transaction.id),
            &state.database_pool,
        )
        .await
        .ok();
        if let Err(error) = AccessPolicy::create(
            &InitialAccessPolicyProperties {
                principal_type: AccessPolicyPrincipalType::Role,
                principal_role_id: Some(user_account_owners_role.id),
                scoped_resource_type: ResourceType::User,
                scoped_user_id: Some(user.id),
                is_inheritance_enabled: true,
                action_id: action.id,
                permission_level: PermissionLevel::User,
                ..Default::default()
            },
            &state.database_pool,
        )
        .await
        {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to add allowed action {} to user account owners role for user {}: {:?}",
                action_name, user.id, error
            )));
            http_error.log();
            return Err(http_error);
        }
    }

    trace!("Creating membership for user in their user account owners role...");

    if let Err(error) = Membership::create(
        &InitialMembershipProperties {
            parent_resource_type: MembershipParentResourceType::Role,
            parent_group_id: None,
            parent_role_id: Some(user_account_owners_role.id),
            principal_user_id: Some(user.id),
            principal_app_id: None,
            principal_group_id: None,
            principal_type: MembershipPrincipalType::User,
        },
        &state.database_pool,
    )
    .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to create membership for user {} in their user account owners role: {:?}",
            user.id, error
        )));
        http_error.log();
        return Err(http_error);
    }

    ServerLogEntry::success(
        &format!("Successfully created registered user {}.", user.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = CreateResourceResponseBody { data: user.clone() };

    Ok((StatusCode::CREATED, Json(response_body)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/users", axum::routing::get(handle_list_users_request))
        .route("/users", axum::routing::post(handle_create_user_request))
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
        .merge(user_id::get_router(state.clone()))
}
