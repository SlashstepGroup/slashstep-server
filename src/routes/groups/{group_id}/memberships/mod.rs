/**
 * 
 * Any functionality for /groups/{group_id}/memberships should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::{sync::Arc};
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use serde::Deserialize;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceError, ResourceType, access_policy::{ActionPermissionLevel, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, membership::{InitialMembershipProperties, InitialMembershipPropertiesWithPredefinedParent, Membership, MembershipParentResourceType}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{can_delegate_perform_action, can_principal_perform_action, get_action_by_name, get_action_log_entry_expiration_timestamp, get_group_by_id, get_membership_invitation_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

#[derive(Debug, Deserialize)]
pub struct CreateMembershipQueryParameters {
  #[serde(rename = "membership-invitation-id")]
  pub membership_invitation_id: Option<String>
}

/// POST /groups/{group_id}/memberships
/// 
/// Creates a new membership for a user in a group.
#[axum::debug_handler]
pub async fn handle_create_membership_request(
  Path(group_id): Path<String>,
  Query(query_parameters): Query<CreateMembershipQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialMembershipPropertiesWithPredefinedParent>, JsonRejection>
) -> Result<(StatusCode, Json<Membership>), HTTPError> {

  let partial_membership_properties = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
  let is_user_only_adding_self = if let Some(authenticated_user) = &authenticated_user { 

    partial_membership_properties.principal_user_id.as_ref() == Some(&authenticated_user.id)

  } else if let Some(authenticated_app) = &authenticated_app { 

    partial_membership_properties.principal_app_id.as_ref() == Some(&authenticated_app.id)

  } else { false };

  // Make sure the principal has access to list resources.
  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  if partial_membership_properties.principal_group_id == Some(group_id) {

    let http_error = HTTPError::UnprocessableEntity(Some("A membership cannot have the same group as both its parent group and principal group.".to_string()));
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }
  let create_memberships_action = get_action_by_name("memberships.create", &http_transaction, &state.database_pool).await?;
  let join_groups_action = get_action_by_name("groups.join", &http_transaction, &state.database_pool).await?;
  let accept_membership_invitations_action = get_action_by_name("membershipInvitations.accept", &http_transaction, &state.database_pool).await?;
  let app_authorization_id = authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id);
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  if let Some(membership_invitation_id) = query_parameters.membership_invitation_id {

    let membership_invitation_id = get_uuid_from_string(&membership_invitation_id, "membership invitation", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(app_authorization_id, &accept_membership_invitations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
    let membership_invitation = get_membership_invitation_by_id(&membership_invitation_id, &http_transaction, &state.database_pool).await?;
    verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::MembershipInvitation, Some(&membership_invitation.id), &accept_membership_invitations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  } else {

    // If the principal can create memberships but doesn't have the permission to add themselves to the group,
    // then the permission to create memberships takes priority over the permission to join groups.
    let can_delegate_add_self = is_user_only_adding_self && can_delegate_perform_action(app_authorization_id, &join_groups_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
    if !can_delegate_add_self {

      verify_delegate_permissions(app_authorization_id, &create_memberships_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;

    };

    let can_principal_add_self = is_user_only_adding_self && can_principal_perform_action(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Group, Some(&target_group.id), &join_groups_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;
    if !can_principal_add_self {

      verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Group, Some(&target_group.id), &create_memberships_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

    }

  }

  let created_membership = match Membership::create(&InitialMembershipProperties {
    principal_type: partial_membership_properties.principal_type.clone(),
    principal_app_id: partial_membership_properties.principal_app_id.clone(),
    principal_user_id: partial_membership_properties.principal_user_id.clone(),
    principal_group_id: partial_membership_properties.principal_group_id.clone(),
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(target_group.id),
    parent_role_id: None
  }, &state.database_pool).await {

    Ok(membership) => membership,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create membership: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_memberships_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp: expiration_timestamp,
    reason: None, // TODO: Support reasons.
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::Membership,
    target_membership_id: Some(created_membership.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  ServerLogEntry::success(&format!("Successfully created membership {}.", created_membership.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(created_membership)));

}

/// GET /groups/{group_id}/memberships
/// 
/// Lists memberships for an app.
#[axum::debug_handler]
pub async fn handle_list_memberships_request(
  Path(group_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<Membership>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("memberships.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Group, Some(&target_group.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_group_id = {}{}", 
    quote_literal(&group_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND ({})", query))).unwrap_or("".to_string())
  );
  let queried_resources = match Membership::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "memberships"),

        ResourceError::PostgresError(error) => match_db_error(&error, "memberships"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list memberships: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting memberships..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match Membership::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count memberships: {:?}", error)));
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
    target_resource_type: ResourceType::Group,
    target_group_id: Some(group_id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "membership" } else { "memberships" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<Membership> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/groups/{group_id}/memberships", axum::routing::get(handle_list_memberships_request))
    .route("/groups/{group_id}/memberships", axum::routing::post(handle_create_membership_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
