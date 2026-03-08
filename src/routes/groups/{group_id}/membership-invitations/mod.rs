/**
 * 
 * Any functionality for /groups/{group_id}/membership-invitations should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{ResourceType, ResourceError, access_policy::{ActionPermissionLevel, DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, membership::{MembershipParentResourceType, MembershipPrincipalType}, membership_invitation::{InitialMembershipInvitationProperties, InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter, MembershipInvitation}, server_log_entry::ServerLogEntry, user::User}, routes::{ListResourcesResponseBody, ResourceListQueryParameters}, utilities::route_handler_utilities::{get_action_by_name, get_action_log_entry_expiration_timestamp, get_group_by_id, get_principal_type_and_id_from_principal, get_request_body_without_json_rejection, get_uuid_from_string, is_authenticated_user_anonymous, match_db_error, match_slashstepql_error, verify_delegate_permissions, verify_principal_permissions}};

/// GET /groups/{group_id}/membership-invitations
/// 
/// Lists membership invitations for an membership invitation.
#[axum::debug_handler]
async fn handle_list_membership_invitations_request(
  Path(group_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<(StatusCode, Json<ListResourcesResponseBody<MembershipInvitation>>), HTTPError> {

  // Make sure the principal has access to list resources.
  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let list_resources_action = get_action_by_name("membershipInvitations.list", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &list_resources_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Group, Some(&target_group.id), &list_resources_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  let query = format!(
    "parent_group_id = {}{}", 
    quote_literal(&group_id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  let queried_resources = match MembershipInvitation::list(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(queried_resources) => queried_resources,

    Err(error) => {

      let http_error = match error {

        ResourceError::SlashstepQLError(error) => match_slashstepql_error(&error, &DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, "membership invitations"),

        ResourceError::PostgresError(error) => match_db_error(&error, "membership invitations"),

        _ => HTTPError::InternalServerError(Some(format!("Failed to list membership invitations: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  ServerLogEntry::trace(&format!("Counting membership invitations..."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let resource_count = match MembershipInvitation::count(&query, &state.database_pool, Some(&principal_type), Some(&principal_id)).await {

    Ok(resource_count) => resource_count,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to count membership invitations: {:?}", error)));
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
    target_group_id: Some(target_group.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  
  let queried_resource_list_length = queried_resources.len();
  ServerLogEntry::success(&format!("Successfully returned {} {}.", queried_resource_list_length, if queried_resource_list_length == 1 { "membership invitation" } else { "membership invitations" }), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response_body = ListResourcesResponseBody::<MembershipInvitation> {
    resources: queried_resources,
    total_count: resource_count
  };
  
  return Ok((StatusCode::OK, Json(response_body)));

}

/// POST /groups/{group_id}/membership-invitations
/// 
/// Creates a membership invitation for an membership invitation.
#[axum::debug_handler]
async fn handle_create_membership_invitation_request(
  Path(group_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
  body: Result<Json<InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter>, JsonRejection>
) -> Result<(StatusCode, Json<MembershipInvitation>), HTTPError> {

  let membership_invitation_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;

  // Make sure the user can create membership invitations for the target action.
  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let create_membership_invitations_action = get_action_by_name("membershipInvitations.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_membership_invitations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let (principal_type, principal_id) = get_principal_type_and_id_from_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&principal_type, &principal_id, is_authenticated_user_anonymous(authenticated_user.as_ref()), &ResourceType::Group, Some(&target_group.id), &create_membership_invitations_action, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

  // Create the membership invitation.
  ServerLogEntry::trace(&format!("Creating membership invitation for group {}...", group_id), Some(&http_transaction.id), &state.database_pool).await.ok();
  let membership_invitation = match MembershipInvitation::create(&InitialMembershipInvitationProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(target_group.id),
    parent_role_id: None,
    invitee_principal_type: membership_invitation_properties_json.invitee_principal_type,
    invitee_principal_user_id: membership_invitation_properties_json.invitee_principal_user_id,
    invitee_principal_group_id: membership_invitation_properties_json.invitee_principal_group_id,
    invitee_principal_app_id: membership_invitation_properties_json.invitee_principal_app_id,
    inviter_principal_type: if authenticated_user.is_some() { MembershipPrincipalType::User } else { MembershipPrincipalType::App },
    inviter_principal_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    inviter_principal_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None }
  }, &state.database_pool).await {

    Ok(membership_invitation) => membership_invitation,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create membership invitation: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

  };

  let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: create_membership_invitations_action.id,
    http_transaction_id: Some(http_transaction.id),
    expiration_timestamp,
    actor_type: if authenticated_user.is_some() { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let Some(authenticated_user) = &authenticated_user { Some(authenticated_user.id.clone()) } else { None },
    actor_app_id: if let Some(authenticated_app) = &authenticated_app { Some(authenticated_app.id.clone()) } else { None },
    target_resource_type: ResourceType::MembershipInvitation,
    target_membership_invitation_id: Some(membership_invitation.id),
    ..Default::default()
  }, &state.database_pool).await.ok();
  ServerLogEntry::success(&format!("Successfully created membership invitation {}.", membership_invitation.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  return Ok((StatusCode::CREATED, Json(membership_invitation)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/groups/{group_id}/membership-invitations", axum::routing::get(handle_list_membership_invitations_request))
    .route("/groups/{group_id}/membership-invitations", axum::routing::post(handle_create_membership_invitation_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
  return router;

}
