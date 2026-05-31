/*
 *
 * Any functionality for /workspaces should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[path = "./{workspace_id}/mod.rs"]
pub mod workspace_id;

use std::sync::Arc;
use tracing::{trace};

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
        http_transaction::HTTPTransaction,
        membership::{
            InitialMembershipProperties, Membership, MembershipParentResourceType,
            MembershipPrincipalType,
        },
        role::{InitialRoleProperties, PredefinedRoleType, Role, RoleParentResourceType},
        server_log_entry::ServerLogEntry,
        user::User,
        workspace::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialWorkspaceProperties, Workspace},
    },
    routes::{ListResourcesResponseBody, ResourceListQueryParameters},
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

/// GET /workspaces
///
/// Lists workspaces.
#[axum::debug_handler]
async fn handle_list_workspaces_request(
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Workspace>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let list_resources_action =
        get_action_by_name("workspaces.list", &http_transaction, &state.database_pool).await?;
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

    trace!("Listing workspaces...");
    let query = query_parameters.query.unwrap_or("".to_string());
    let queried_resources = match Workspace::list(
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
                ResourceError::SlashstepQLError(error) => match_slashstepql_error(
                    &error,
                    &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
                    "workspaces",
                ),

                ResourceError::PostgresError(error) => match_db_error(&error, "workspaces"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list workspaces: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Counting workspaces...");
    let resource_count = match Workspace::count(
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
                "Failed to count workspaces: {:?}",
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

    let queried_workspace_list_length = queried_resources.len();
    ServerLogEntry::success(
        &format!(
            "Successfully returned {} {}.",
            queried_workspace_list_length,
            if queried_workspace_list_length == 1 {
                "workspace"
            } else {
                "workspaces"
            }
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = ListResourcesResponseBody::<Workspace> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateWorkspaceRequestBody {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

/// POST /workspaces
///
/// Creates a workspace on the server level.
#[axum::debug_handler]
async fn handle_create_workspace_request(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<CreateWorkspaceRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<Workspace>), HTTPError> {
    let create_workspace_request_body =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    validate_resource_name(
        &create_workspace_request_body.name,
        "workspaces.allowedNameRegex",
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_workspace_request_body.name,
        "workspaces.maximumNameLength",
        "name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &create_workspace_request_body.display_name,
        "workspaces.maximumDisplayNameLength",
        "display name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;

    if let Some(description) = &create_workspace_request_body.description {
        validate_field_length(
            description,
            "workspaces.maximumDescriptionLength",
            "description",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }

    // Make sure the authenticated_user can create apps for the target action log entry.
    let create_workspaces_action =
        get_action_by_name("workspaces.create", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_workspaces_action.id,
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
        &create_workspaces_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    // Create the workspace.
    trace!("Creating workspace...");
    let workspace = match Workspace::create(
        &InitialWorkspaceProperties {
            name: create_workspace_request_body.name.clone(),
            display_name: create_workspace_request_body.display_name.clone(),
            description: create_workspace_request_body.description.clone(),
        },
        &state.database_pool,
    )
    .await
    {
        Ok(workspace) => workspace,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create workspace: {:?}",
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
            action_id: create_workspaces_action.id,
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
            target_resource_type: ResourceType::Workspace,
            target_workspace_id: Some(workspace.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    trace!("Creating workspace admins role on workspace...");

    let workspace_admins_role = match Role::create(
        &InitialRoleProperties {
            name: "workspace-admins".to_string(),
            display_name: "Workspace admins".to_string(),
            description: Some(
                "Principals who have administrative privileges for a workspace.".to_string(),
            ),
            parent_resource_type: RoleParentResourceType::Workspace,
            parent_group_id: None,
            parent_project_id: None,
            parent_user_id: None,
            parent_workspace_id: Some(workspace.id),
            parent_app_id: None,
            predefined_role_type: Some(PredefinedRoleType::WorkspaceAdmins),
        },
        &state.database_pool,
    )
    .await
    {
        Ok(role) => role,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create workspace admins role on workspace {}: {:?}",
                workspace.id, error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    trace!("Creating access policies for workspace admins role...");

    let allowed_actions = vec![
        "accessPolicies.create",
        "accessPolicies.get",
        "accessPolicies.list",
        "accessPolicies.update",
        "accessPolicies.delete",
        "actions.create",
        "actions.get",
        "actions.list",
        "actions.update",
        "actions.delete",
        "actionLogEntries.get",
        "actionLogEntries.list",
        "apps.authorize",
        "apps.get",
        "apps.list",
        "apps.create",
        "apps.update",
        "apps.delete",
        "appAuthorizations.create",
        "appAuthorizations.delete",
        "appAuthorizations.get",
        "appAuthorizations.list",
        "appCredentials.create",
        "appCredentials.delete",
        "appCredentials.get",
        "appCredentials.list",
        "fields.create",
        "fields.delete",
        "fields.get",
        "fields.list",
        "fields.update",
        "fieldChoices.create",
        "fieldChoices.delete",
        "fieldChoices.get",
        "fieldChoices.list",
        "fieldChoices.update",
        "fieldValues.create",
        "fieldValues.delete",
        "fieldValues.get",
        "fieldValues.list",
        "fieldValues.update",
        "items.create",
        "items.delete",
        "items.get",
        "items.list",
        "items.update",
        "itemConnections.create",
        "itemConnections.delete",
        "itemConnections.get",
        "itemConnections.list",
        "itemConnections.update",
        "itemConnectionTypes.create",
        "itemConnectionTypes.delete",
        "itemConnectionTypes.get",
        "itemConnectionTypes.list",
        "itemConnectionTypes.update",
        "itemTypes.create",
        "itemTypes.delete",
        "itemTypes.get",
        "itemTypes.list",
        "itemTypes.update",
        "itemTypeIcons.create",
        "itemTypeIcons.delete",
        "itemTypeIcons.get",
        "itemTypeIcons.list",
        "itemTypeIcons.update",
        "iterations.create",
        "iterations.delete",
        "iterations.get",
        "iterations.list",
        "iterations.update",
        "milestones.create",
        "milestones.delete",
        "milestones.get",
        "milestones.list",
        "milestones.update",
        "projects.create",
        "projects.delete",
        "projects.get",
        "projects.list",
        "projects.update",
        "roles.create",
        "roles.delete",
        "roles.get",
        "roles.list",
        "roles.update",
        "statuses.create",
        "statuses.delete",
        "statuses.get",
        "statuses.list",
        "statuses.update",
        "views.create",
        "views.delete",
        "views.get",
        "views.list",
        "views.update",
        "viewFields.create",
        "viewFields.delete",
        "viewFields.get",
        "viewFields.list",
        "viewFields.update",
        "workspaces.delete",
        "workspaces.get",
        "workspaces.list",
        "workspaces.update",
    ];

    let principal_type_str = if principal_type == AccessPolicyPrincipalType::User {
        "user"
    } else {
        "app"
    };
    for action_name in allowed_actions {
        let action =
            get_action_by_name(action_name, &http_transaction, &state.database_pool).await?;

        ServerLogEntry::trace(
            &format!(
                "Creating access policy for action {} in workspace admins role...",
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
                principal_role_id: Some(workspace_admins_role.id),
                scoped_resource_type: if principal_type == AccessPolicyPrincipalType::User {
                    ResourceType::User
                } else {
                    ResourceType::App
                },
                scoped_user_id: if principal_type == AccessPolicyPrincipalType::User {
                    Some(principal_id)
                } else {
                    None
                },
                scoped_app_id: if principal_type == AccessPolicyPrincipalType::App {
                    Some(principal_id)
                } else {
                    None
                },
                is_inheritance_enabled: true,
                action_id: action.id,
                permission_level: PermissionLevel::Admin,
                ..Default::default()
            },
            &state.database_pool,
        )
        .await
        {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to add allowed action {} to workspace admins role for {} {}: {:?}",
                action_name, principal_type_str, principal_id, error
            )));
            http_error.log();
            return Err(http_error);
        }
    }

    ServerLogEntry::trace(
        &format!(
            "Creating membership for {} {} in their workspace admins role...",
            principal_type_str, principal_id
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    if let Err(error) = Membership::create(
        &InitialMembershipProperties {
            parent_resource_type: MembershipParentResourceType::Role,
            parent_group_id: None,
            parent_role_id: Some(workspace_admins_role.id),
            principal_user_id: if principal_type == AccessPolicyPrincipalType::User {
                Some(principal_id)
            } else {
                None
            },
            principal_app_id: if principal_type == AccessPolicyPrincipalType::App {
                Some(principal_id)
            } else {
                None
            },
            principal_group_id: None,
            principal_type: if principal_type == AccessPolicyPrincipalType::User {
                MembershipPrincipalType::User
            } else {
                MembershipPrincipalType::App
            },
        },
        &state.database_pool,
    )
    .await
    {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to create membership for {} {} in their workspace admins role: {:?}",
            principal_type_str, principal_id, error
        )));
        http_error.log();
        return Err(http_error);
    }

    ServerLogEntry::success(
        &format!("Successfully created workspace {}.", workspace.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    Ok((StatusCode::CREATED, Json(workspace)))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/workspaces",
            axum::routing::get(handle_list_workspaces_request),
        )
        .route(
            "/workspaces",
            axum::routing::post(handle_create_workspace_request),
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
        .merge(workspace_id::get_router(state.clone()))
}
