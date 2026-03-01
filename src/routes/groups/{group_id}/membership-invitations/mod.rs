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
use axum_extra::response::ErasedJson;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{access_policy::{AccessPolicyResourceType, ActionPermissionLevel, DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT, InitialAccessPolicyProperties, InitialAccessPolicyPropertiesForPredefinedScope}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, http_transaction::HTTPTransaction, membership::{MembershipParentResourceType, MembershipPrincipalType}, membership_invitation::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, InitialMembershipInvitationProperties, InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter, MembershipInvitation}, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_id, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_group_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, verify_delegate_permissions, verify_principal_permissions}}};

/// GET /groups/{group_id}/membership-invitations
/// 
/// Lists membership invitations for an app credential.
#[axum::debug_handler]
async fn handle_list_membership_invitations_request(
  Path(group_id): Path<String>,
  Query(query_parameters): Query<ResourceListQueryParameters>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(authenticated_user): Extension<Option<Arc<User>>>,
  Extension(authenticated_app): Extension<Option<Arc<App>>>,
  Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
) -> Result<ErasedJson, HTTPError> {

  let group_id = get_uuid_from_string(&group_id, "group", &http_transaction, &state.database_pool).await?;
  let target_group = get_group_by_id(&group_id, &http_transaction, &state.database_pool).await?;
  let resource_hierarchy = get_resource_hierarchy(&target_group, &AccessPolicyResourceType::Group, &target_group.id, &http_transaction, &state.database_pool).await?;

  let query = format!(
    "parent_resource_type = 'Group' AND parent_group_id = {}{}", 
    quote_literal(&target_group.id.to_string()), 
    query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
  );
  
  let query_parameters = ResourceListQueryParameters {
    query: Some(query)
  };

  let response = list_resources(
    Query(query_parameters), 
    State(state), 
    Extension(http_transaction), 
    Extension(authenticated_user), 
    Extension(authenticated_app), 
    Extension(authenticated_app_authorization),
    resource_hierarchy, 
    ActionLogEntryTargetResourceType::Group, 
    Some(target_group.id), 
    |query, database_pool, individual_principal| Box::new(MembershipInvitation::count(query, database_pool, individual_principal)),
    |query, database_pool, individual_principal| Box::new(MembershipInvitation::list(query, database_pool, individual_principal)),
    "membershipInvitations.list", 
    DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
    "membership invitations",
    "membership invitation"
  ).await;
  
  return response;

}

/// POST /groups/{group_id}/membership-invitations
/// 
/// Creates a membership invitation for an app credential.
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
  let resource_hierarchy = get_resource_hierarchy(&target_group, &AccessPolicyResourceType::Group, &target_group.id, &http_transaction, &state.database_pool).await?;
  let create_membership_invitations_action = get_action_by_name("membershipInvitations.create", &http_transaction, &state.database_pool).await?;
  verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_membership_invitations_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
  let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
  verify_principal_permissions(&authenticated_principal, &create_membership_invitations_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

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
    inviter_principal_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { MembershipPrincipalType::User } else { MembershipPrincipalType::App },
    inviter_principal_user_id: authenticated_user.as_ref().map(|user| user.id),
    inviter_principal_app_id: authenticated_app.as_ref().map(|app| app.id)
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
    actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
    actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
    actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
    target_resource_type: ActionLogEntryTargetResourceType::MembershipInvitation,
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
