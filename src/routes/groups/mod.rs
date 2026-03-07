/**
 * 
 * Any functionality for /groups should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[path = "./{group_id}/mod.rs"]
mod group_id;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{Extension, Json, Router, extract::{Query, State, rejection::JsonRejection}};
use reqwest::StatusCode;
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPrincipalType, ResourceType, ActionPermissionLevel, InitialAccessPolicyProperties}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, group::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, Group, InitialGroupProperties}, http_transaction::HTTPTransaction, membership::{InitialMembershipProperties, Membership, MembershipParentResourceType, MembershipPrincipalType}, role::{InitialRoleProperties, ProtectedRoleType, Role, RoleParentResourceType}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::{route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_request_body_without_json_rejection, match_db_error, match_slashstepql_error, validate_field_length, validate_resource_name, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /groups
/// 
/// Lists groups.
#[axum::debug_handler]
async fn handle_list_groups_request(
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Group>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let list_resources_action = get_action_by_name("groups.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Server, None, &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  ServerLogEntry::trace("Listing groups...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let query = query_parameters.query.unwrap_or("".to_string());
  let queried_resources = match Group::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "groups"),

        ResourceError::PostgresError(error) => match_db_error(&error, "groups"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list groups: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting groups..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Group::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count groups: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: list_resources_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Server,
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_group_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_group_list_length, if queried_group_list_length == 1 { "group" } else { "groups" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Group> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

async fn create_role(initial_role_properties: &InitialRoleProperties, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Role, HTTPError> {

  ServerLogEntry::trace(&format!("Creating role \"{}\"...", initial_role_properties.name), Some(&http_transaction_id), database_pool).await.ok();

  match Role::create(initial_role_properties, database_pool).await {

    Ok(role) => Ok(role),

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create role: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(http_transaction_id), database_pool).await.ok();
      Err(http_error)

    }

  }

}

async fn create_membership(initial_membership_properties: &InitialMembershipProperties, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Membership, HTTPError> {

  ServerLogEntry::trace(&format!("Creating membership for principal..."), Some(http_transaction_id), database_pool).await.ok();

  match Membership::create(initial_membership_properties, database_pool).await {

    Ok(membership) => Ok(membership),

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create membership: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(http_transaction_id), database_pool).await.ok();
      Err(http_error)

    }

  }

}

async fn create_default_child_resources(group: &Group, http_transaction: &HTTPTransaction, database_pool: &deadpool_postgres::Pool, authenticated_principal: &AuthenticatedPrincipal) -> Result<(), HTTPError> {

  ServerLogEntry::trace("Creating default child resources for group...", Some(&http_transaction.id), database_pool).await.ok();

  let group_admins_role = create_role(&InitialRoleProperties {
    name: "group-admins".to_string(),
    display_name: "Group admins".to_string(),
    description: Some("Group admins can manage the group, including its metadata and its members.".to_string()),
    parent_resource_type: RoleParentResourceType::Group,
    parent_group_id: Some(group.id),
    protected_role_type: Some(ProtectedRoleType::GroupAdmins),
    ..Default::default()
  }, &http_transaction.id, &database_pool).await?;
  let group_admin_action_names = vec![
    "accessPolicies.create",
    "accessPolicies.get",
    "accessPolicies.list",
    "accessPolicies.update",
    "accessPolicies.delete",
    "actionLogEntries.get",
    "actionLogEntries.list",
    "groups.get",
    "groups.list",
    "groups.update",
    "groups.delete",
    "memberships.delete",
    "memberships.renounce",
    "memberships.get",
    "memberships.list",
    "membershipInvitations.get",
    "membershipInvitations.list",
    "membershipInvitations.create",
    "membershipInvitations.delete",
    "roles.get",
    "roles.list",
    "roles.create",
    "roles.update",
    "roles.delete"
  ];

  for group_admin_action_name in group_admin_action_names {

    let group_admin_action = get_action_by_name(group_admin_action_name, &http_transaction, &database_pool).await?;
    match AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: group_admin_action.id,
      permission_level: ActionPermissionLevel::Admin,
      is_inheritance_enabled: true,
      principal_type: AccessPolicyPrincipalType::Role,
      principal_role_id: Some(group_admins_role.id),
      scoped_resource_type: ResourceType::Group,
      scoped_group_id: Some(group.id),
      ..Default::default()
    }, &database_pool).await {

      Ok(_) => (),

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to grant admin access to {} action for group admin role: {:?}", group_admin_action_name, error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };

  }

  create_membership(&InitialMembershipProperties {
    parent_resource_type: MembershipParentResourceType::Role,
    parent_role_id: Some(group_admins_role.id),
    principal_type: if let AuthenticatedPrincipal::User(_) = authenticated_principal { MembershipPrincipalType::User } else { MembershipPrincipalType::App },
    principal_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    principal_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    ..Default::default()
  }, &http_transaction.id, &database_pool).await?;

  ServerLogEntry::info("Successfully created group admins role and added the authenticated principal to it.", Some(&http_transaction.id), &database_pool).await.ok();

  let group_members_role = create_role(&InitialRoleProperties {
    name: "group-members".to_string(),
    display_name: "Group members".to_string(),
    description: Some("Group members can view the group's metadata and its members.".to_string()),
    parent_resource_type: RoleParentResourceType::Group,
    parent_group_id: Some(group.id),
    protected_role_type: Some(ProtectedRoleType::GroupMembers),
    ..Default::default()
  }, &http_transaction.id, &database_pool).await?;
  let group_member_action_names = vec![
    "accessPolicies.get",
    "accessPolicies.list",
    "groups.get",
    "groups.list",
    "groups.update",
    "groups.delete",
    "memberships.renounce",
    "memberships.get",
    "memberships.list",
    "roles.get",
    "roles.list"
  ];

  for group_member_action_name in group_member_action_names {

    let group_member_action = get_action_by_name(group_member_action_name, &http_transaction, &database_pool).await?;
    match AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: group_member_action.id,
      permission_level: ActionPermissionLevel::User,
      is_inheritance_enabled: true,
      principal_type: AccessPolicyPrincipalType::Role,
      principal_role_id: Some(group_members_role.id),
      scoped_resource_type: ResourceType::Group,
      scoped_group_id: Some(group.id),
      ..Default::default()
    }, &database_pool).await {

      Ok(_) => (),

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to grant user access to {} action for group member role: {:?}", group_member_action_name, error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &database_pool).await.ok();
        return Err(http_error);

      }

    };

  }

  create_membership(&InitialMembershipProperties {
    parent_resource_type: MembershipParentResourceType::Role,
    parent_role_id: Some(group_members_role.id),
    principal_type: if let AuthenticatedPrincipal::User(_) = authenticated_principal { MembershipPrincipalType::User } else { MembershipPrincipalType::App },
    principal_user_id: if let AuthenticatedPrincipal::User(authenticated_user) = authenticated_principal { Some(authenticated_user.id.clone()) } else { None },
    principal_app_id: if let AuthenticatedPrincipal::App(authenticated_app) = authenticated_principal { Some(authenticated_app.id.clone()) } else { None },
    ..Default::default()
  }, &http_transaction.id, &database_pool).await?;

  ServerLogEntry::info("Successfully created group members role and added the authenticated principal to it.", Some(&http_transaction.id), &database_pool).await.ok();

  return Ok(());

}

/// POST /groups
/// 
/// Creates a group on the server level.
#[axum::debug_handler]
async fn handle_create_group_request(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialGroupProperties>, JsonRejection>
) -> Result<(StatusCode, Json<Group>), HTTPError> {

  // TODO: Add configurations to verify inputs.
  let initial_group_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  validate_resource_name(&initial_group_properties.name, "groups.allowedNameRegex", "group", &http_transaction, &state.database_pool).await?;
  validate_field_length(&initial_group_properties.name, "groups.maximumNameLength", "name", &http_transaction, &state.database_pool).await?;
  validate_field_length(&initial_group_properties.display_name, "groups.maximumDisplayNameLength", "display name", &http_transaction, &state.database_pool).await?;
  if let Some(field_description) = &initial_group_properties.description {

    validate_field_length(field_description, "groups.maximumDescriptionLength", "description", &http_transaction, &state.database_pool).await?;

  }

  // Make sure the authenticated_user can create apps for the target action log entry.
  let create_groups_action = get_action_by_name("groups.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_groups_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  verify_principal_permissions(&authenticated_principal, &create_groups_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the group.
  ServerLogEntry::trace("Creating group...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let group = match Group::create(&initial_group_properties, &state.database_pool).await {

    Ok(group) => group,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create group: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_groups_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::Group,
    target_group_id: Some(group.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::info(&format!("Successfully created group {}.", group.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  if let Err(error) = create_default_child_resources(&group, &http_transaction, &state.database_pool, &authenticated_principal).await {

    ServerLogEntry::trace("Deleting group due to error creating default child resources...", Some(&http_transaction.id), &state.database_pool).await.ok();
    if let Err(delete_error) = group.delete(&state.database_pool).await {
        
      let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete group after error creating default child resources: {:?}", delete_error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    };

    ServerLogEntry::info("Successfully deleted group.", Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(error);

  };

  ServerLogEntry::success(&format!("Successfully created group {} with default child resources.", group.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(group)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/groups", axum::routing::get(handle_list_groups_request))
    .route("/groups", axum::routing::post(handle_create_group_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction))
    .merge(group_id::get_router(state.clone()));
  return router;

}