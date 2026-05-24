/**
 *
 * Any functionality for /workspaces/{workspace_id}/apps should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

#[cfg(test)]
mod tests;

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
        app::{
            App, AppClientType, AppParentResourceType, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
            InitialAppProperties,
        },
        app_authorization::AppAuthorization,
        http_transaction::HTTPTransaction,
        role::{InitialRoleProperties, PredefinedRoleType, Role, RoleParentResourceType},
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{
        AppWithClientSecret, CreateAppRequestBody, ListResourcesResponseBody,
        ResourceListQueryParameters,
    },
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, get_workspace_by_id, is_authenticated_user_anonymous, match_db_error,
        match_slashstepql_error, validate_field_length, validate_resource_display_name,
        validate_resource_name, verify_delegate_permissions, verify_principal_permissions,
    },
};
use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State, rejection::JsonRejection},
};
use pg_escape::quote_literal;
use rand::{RngExt, distr::Alphanumeric};
use reqwest::StatusCode;
use std::sync::Arc;

/// GET /workspaces/{workspace_id}/apps
///
/// Lists apps for a workspace.
#[axum::debug_handler]
async fn handle_list_apps_request(
    Path(workspace_id): Path<String>,
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<(StatusCode, Json<ListResourcesResponseBody<App>>), HTTPError> {
    // Make sure the principal has access to list resources.
    let workspace_id = get_uuid_from_string(
        &workspace_id,
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let list_resources_action =
        get_action_by_name("apps.list", &http_transaction, &state.database_pool).await?;
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
    let target_workspace =
        get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::Workspace,
        Some(&target_workspace.id),
        &list_resources_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let query = format!(
        "parent_workspace_id = {}{}",
        quote_literal(&workspace_id.to_string()),
        query_parameters
            .query.map(|query| format!(" AND ({})", query))
            .unwrap_or("".to_string())
    );
    let queried_resources = match App::list(
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
                    match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "apps")
                }

                ResourceError::PostgresError(error) => match_db_error(&error, "apps"),

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to list apps: {:?}",
                    error
                ))),
            };

            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    ServerLogEntry::trace(
        "Counting apps...",
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let resource_count = match App::count(
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
                HTTPError::InternalServerError(Some(format!("Failed to count apps: {:?}", error)));
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
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
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::Workspace,
            target_workspace_id: Some(workspace_id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    let queried_resource_list_length = queried_resources.len();
    ServerLogEntry::success(
        &format!(
            "Successfully returned {} {}.",
            queried_resource_list_length,
            if queried_resource_list_length == 1 {
                "app"
            } else {
                "apps"
            }
        ),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let response_body = ListResourcesResponseBody::<App> {
        data: queried_resources,
        total_count: resource_count,
    };

    Ok((StatusCode::OK, Json(response_body)))
}

/// POST /workspaces/{workspace_id}/apps
///
/// Creates a app for an workspace.
#[axum::debug_handler]
async fn handle_create_app_request(
    Path(workspace_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<CreateAppRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<AppWithClientSecret>), HTTPError> {
    let app_properties_json =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    validate_resource_name(
        &app_properties_json.name,
        "apps.allowedNameRegex",
        "app",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &app_properties_json.name,
        "apps.maximumNameLength",
        "name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_resource_display_name(
        &app_properties_json.display_name,
        "apps.allowedDisplayNameRegex",
        "app",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    validate_field_length(
        &app_properties_json.display_name,
        "apps.maximumDisplayNameLength",
        "display_name",
        &http_transaction,
        &state.database_pool,
    )
    .await?;

    let workspace_id = get_uuid_from_string(
        &workspace_id,
        "workspace",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let workspace =
        get_workspace_by_id(&workspace_id, &http_transaction, &state.database_pool).await?;

    // Make sure the authenticated_user can create apps for the target action log entry.
    let create_apps_action =
        get_action_by_name("apps.create", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &create_apps_action.id,
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
        &create_apps_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let mut client_secret_hash = None;
    let mut client_secret = None;
    if app_properties_json.client_type == AppClientType::Confidential {
        ServerLogEntry::trace(
            "Generating client secret for confidential app...",
            Some(&http_transaction.id),
            &state.database_pool,
        )
        .await
        .ok();
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let some_client_secret = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        client_secret = Some(some_client_secret.clone());
        client_secret_hash = match argon2.hash_password(some_client_secret.as_bytes(), &salt) {
            Ok(hash) => Some(hash.to_string()),

            Err(error) => {
                let http_error = HTTPError::InternalServerError(Some(format!(
                    "Failed to hash client secret: {:?}",
                    error
                )));
                ServerLogEntry::from_http_error(
                    &http_error,
                    Some(&http_transaction.id),
                    &state.database_pool,
                )
                .await
                .ok();
                return Err(http_error);
            }
        };
    }

    // Create the app.
    ServerLogEntry::trace(
        "Creating app for server...",
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();
    let app = match App::create(
        &InitialAppProperties {
            name: app_properties_json.name.clone(),
            display_name: app_properties_json.display_name.clone(),
            description: app_properties_json.description.clone(),
            parent_resource_type: AppParentResourceType::Workspace,
            client_type: app_properties_json.client_type.clone(),
            client_secret_hash,
            parent_workspace_id: Some(workspace.id),
            parent_user_id: None,
        },
        &state.database_pool,
    )
    .await
    {
        Ok(app) => app,

        Err(error) => {
            let http_error =
                HTTPError::InternalServerError(Some(format!("Failed to create app: {:?}", error)));
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: create_apps_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user.as_ref().map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app.as_ref().map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::App,
            target_app_id: Some(app.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    ServerLogEntry::trace(
        "Creating app admins role for app...",
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let app_admins_role = match Role::create(
        &InitialRoleProperties {
            name: "app-admins".to_string(),
            display_name: "App admins".to_string(),
            description: Some(
                "Principals who have administrative privileges for an app.".to_string(),
            ),
            parent_resource_type: RoleParentResourceType::App,
            parent_group_id: None,
            parent_project_id: None,
            parent_user_id: None,
            parent_app_id: Some(app.id),
            parent_workspace_id: None,
            predefined_role_type: Some(PredefinedRoleType::AppAdmins),
        },
        &state.database_pool,
    )
    .await
    {
        Ok(role) => role,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to create app admins role on app {}: {:?}",
                workspace.id, error
            )));
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    };

    ServerLogEntry::trace(
        "Creating access policies for app admins role...",
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    let allowed_actions = vec![
        "actions.create",
        "actions.delete",
        "actions.get",
        "actions.list",
        "actions.update",
        "actionLogEntries.get",
        "actionLogEntries.list",
        "apps.delete",
        "apps.get",
        "apps.list",
        "apps.update",
        "appCredentials.create",
        "appCredentials.delete",
        "appCredentials.get",
        "appCredentials.list",
        "roles.create",
        "roles.delete",
        "roles.get",
        "roles.list",
        "roles.update",
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
                principal_role_id: Some(app_admins_role.id),
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
            ServerLogEntry::from_http_error(
                &http_error,
                Some(&http_transaction.id),
                &state.database_pool,
            )
            .await
            .ok();
            return Err(http_error);
        }
    }

    ServerLogEntry::success(
        &format!("Successfully created app {}.", app.id),
        Some(&http_transaction.id),
        &state.database_pool,
    )
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(AppWithClientSecret {
            id: app.id,
            name: app.name,
            display_name: app.display_name,
            description: app.description,
            client_type: app.client_type,
            client_secret,
            parent_resource_type: app.parent_resource_type,
            parent_workspace_id: app.parent_workspace_id,
            parent_user_id: app.parent_user_id,
        }),
    ))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    
    Router::<AppState>::new()
        .route(
            "/workspaces/{workspace_id}/apps",
            axum::routing::get(handle_list_apps_request),
        )
        .route(
            "/workspaces/{workspace_id}/apps",
            axum::routing::post(handle_create_app_request),
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
}
