/**
 * 
 * Any test cases for /groups/{group_id}/membership-invitations should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::net::SocketAddr;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use pg_escape::quote_literal;
use reqwest::StatusCode;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_configurations, initialize_predefined_roles}, resources::{access_policy::{ActionPermissionLevel, IndividualPrincipal}, action::Action, membership::{MembershipParentResourceType, MembershipPrincipalType}, membership_invitation::{DEFAULT_RESOURCE_LIST_LIMIT, InitialMembershipInvitationProperties, InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter, MembershipInvitation, MembershipInvitationInviteePrincipalType}}, tests::{TestEnvironment, TestSlashstepServerError}, utilities::reusable_route_handlers::ListResourcesResponseBody};

#[tokio::test]
async fn verify_successful_membership_invitation_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Give the user access to the "membershipInvitations.create" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let create_membership_invitations_action = Action::get_by_name("membershipInvitations.create", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &create_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Set up the server and send the request.
  let dummy_group = test_environment.create_random_group().await?;
  let dummy_user = test_environment.create_random_user().await?;
  let initial_membership_invitation_properties = InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter {
    invitee_principal_type: MembershipInvitationInviteePrincipalType::User,
    invitee_principal_user_id: Some(dummy_user.id),
    ..Default::default()
  };
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post(&format!("/groups/{}/membership-invitations", dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .json(&serde_json::json!(initial_membership_invitation_properties))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::CREATED);

  let response_membership_invitation: MembershipInvitation = response.json();
  assert_eq!(response_membership_invitation.parent_group_id, Some(dummy_group.id));
  assert_eq!(response_membership_invitation.invitee_principal_type, initial_membership_invitation_properties.invitee_principal_type);
  assert_eq!(response_membership_invitation.invitee_principal_user_id, initial_membership_invitation_properties.invitee_principal_user_id);
  assert_eq!(response_membership_invitation.invitee_principal_group_id, initial_membership_invitation_properties.invitee_principal_group_id);
  assert_eq!(response_membership_invitation.invitee_principal_app_id, initial_membership_invitation_properties.invitee_principal_app_id);
  assert_eq!(response_membership_invitation.inviter_principal_type, MembershipPrincipalType::User);
  assert_eq!(response_membership_invitation.inviter_principal_user_id, Some(user.id));
  assert_eq!(response_membership_invitation.inviter_principal_app_id, None);

  return Ok(());
  
}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_membership_invitation_list_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "membershipInvitations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_membership_invitations_action = Action::get_by_name("membershipInvitations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "membershipInvitations.list" action.
  let list_membership_invitations_action = Action::get_by_name("membershipInvitations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;
  let dummy_user = test_environment.create_random_user().await?;
  let shown_membership_invitation = MembershipInvitation::create(&InitialMembershipInvitationProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(dummy_group.id),
    parent_role_id: None,
    invitee_principal_type: MembershipInvitationInviteePrincipalType::User,
    invitee_principal_user_id: Some(dummy_user.id),
    invitee_principal_group_id: None,
    invitee_principal_app_id: None,
    inviter_principal_type: MembershipPrincipalType::User,
    inviter_principal_user_id: Some(user.id),
    inviter_principal_app_id: None
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_membership_invitations: ListResourcesResponseBody::<MembershipInvitation> = response.json();
  assert_eq!(response_membership_invitations.total_count, 1);
  assert_eq!(response_membership_invitations.resources.len(), 1);

  let query = format!("parent_group_id = {}", quote_literal(&dummy_group.id.to_string()));
  let actual_membership_invitation_count = MembershipInvitation::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_membership_invitations.total_count, actual_membership_invitation_count);

  let actual_membership_invitations = MembershipInvitation::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_membership_invitations.resources.len(), actual_membership_invitations.len());
  assert_eq!(response_membership_invitations.resources[0].id, actual_membership_invitations[0].id);
  assert_eq!(response_membership_invitations.resources[0].id, shown_membership_invitation.id);

  return Ok(());

}

/// Verifies that the router can return a 200 status code and the requested access policy list.
#[tokio::test]
async fn verify_returned_resource_list_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "membershipInvitations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_membership_invitations_action = Action::get_by_name("membershipInvitations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "membershipInvitations.list" action.
  let list_membership_invitations_action = Action::get_by_name("membershipInvitations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Create a few dummy access policies.
  let dummy_group = test_environment.create_random_group().await?;
  let dummy_user = test_environment.create_random_user().await?;
  let shown_membership_invitation = MembershipInvitation::create(&InitialMembershipInvitationProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(dummy_group.id),
    parent_role_id: None,
    invitee_principal_type: MembershipInvitationInviteePrincipalType::User,
    invitee_principal_user_id: Some(dummy_user.id),
    invitee_principal_group_id: None,
    invitee_principal_app_id: None,
    inviter_principal_type: MembershipPrincipalType::User,
    inviter_principal_user_id: Some(user.id),
    inviter_principal_app_id: None
  }, &test_environment.database_pool).await?;

  // Set up the server and send the request.
  let additional_query = format!("invitee_principal_type = 'User'");
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", &session_token)))
    .add_query_param("query", &additional_query)
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_membership_invitations: ListResourcesResponseBody::<MembershipInvitation> = response.json();
  assert_eq!(response_membership_invitations.total_count, 1);
  assert_eq!(response_membership_invitations.resources.len(), 1);

  let query = format!("parent_group_id = {} AND {}", quote_literal(&dummy_group.id.to_string()), additional_query);
  let actual_membership_invitation_count = MembershipInvitation::count(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_membership_invitations.total_count, actual_membership_invitation_count);

  let actual_membership_invitations = MembershipInvitation::list(&query, &test_environment.database_pool, Some(&IndividualPrincipal::User(user.id))).await?;
  assert_eq!(response_membership_invitations.resources.len(), actual_membership_invitations.len());
  assert_eq!(response_membership_invitations.resources[0].id, actual_membership_invitations[0].id);
  assert_eq!(response_membership_invitations.resources[0].id, shown_membership_invitation.id);

  return Ok(());

}

/// Verifies that the default access policy list limit is enforced.
#[tokio::test]
async fn verify_default_resource_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Give the user access to the "membershipInvitations.get" action.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_membership_invitations_action = Action::get_by_name("membershipInvitations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Give the user access to the "membershipInvitations.list" action.
  let list_membership_invitations_action = Action::get_by_name("membershipInvitations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy access policies.
  let dummy_group = test_environment.create_random_group().await?;
  for _ in 0..(DEFAULT_RESOURCE_LIST_LIMIT + 1) {

    let dummy_user = test_environment.create_random_user().await?;
    let shown_membership_invitation = MembershipInvitation::create(&InitialMembershipInvitationProperties {
      parent_resource_type: MembershipParentResourceType::Group,
      parent_group_id: Some(dummy_group.id),
      parent_role_id: None,
      invitee_principal_type: MembershipInvitationInviteePrincipalType::User,
      invitee_principal_user_id: Some(dummy_user.id),
      invitee_principal_group_id: None,
      invitee_principal_app_id: None,
      inviter_principal_type: MembershipPrincipalType::User,
      inviter_principal_user_id: Some(user.id),
      inviter_principal_app_id: None
    }, &test_environment.database_pool).await?;

  }

  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::OK);

  let response_body: ListResourcesResponseBody::<MembershipInvitation> = response.json();
  assert_eq!(response_body.resources.len(), DEFAULT_RESOURCE_LIST_LIMIT as usize);

  return Ok(());

}

/// Verifies that the server returns a 422 status code when the provided limit is over the maximum limit.
#[tokio::test]
async fn verify_maximum_membership_invitation_list_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_membership_invitations_action = Action::get_by_name("membershipInvitations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_membership_invitations_action.id, &ActionPermissionLevel::User).await?;
  let list_membership_invitations_action = Action::get_by_name("membershipInvitations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .add_query_param("query", format!("LIMIT {}", DEFAULT_RESOURCE_LIST_LIMIT + 1))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  return Ok(());

}

/// Verifies that the server returns a 400 status code when the query is invalid.
#[tokio::test]
async fn verify_query_when_listing_membership_invitations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;
  
  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;
  let get_membership_invitations_action = Action::get_by_name("membershipInvitations.get", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &get_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  let list_membership_invitations_action = Action::get_by_name("membershipInvitations.list", &test_environment.database_pool).await?;
  test_environment.create_server_access_policy(&user.id, &list_membership_invitations_action.id, &ActionPermissionLevel::User).await?;

  // Create dummy resources.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;

  let bad_requests = vec![
    test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
      .add_query_param("query", format!("SELECT * FROM membership_invitations")),
    test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
      .add_query_param("query", format!("SELECT PG_SLEEP(10)")),
    test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
      .add_query_param("query", format!("SELECT * FROM membership_invitations WHERE action_id = {}", get_membership_invitations_action.id))
  ];
  
  for request in bad_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

  }

  let unprocessable_entity_requests = vec![
    test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
      .add_query_param("query", format!("action_ied = {}", get_membership_invitations_action.id)),
    test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
      .add_query_param("query", format!("1 = 1"))
  ];

  for request in unprocessable_entity_requests {

    let response = request
      .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
      .await;

    assert_eq!(response.status_code(), StatusCode::UNPROCESSABLE_ENTITY);

  }

  return Ok(());

}

/// Verifies that the server returns a 401 status code when the user lacks permissions and is unauthenticated.
#[tokio::test]
async fn verify_authentication_when_listing_membership_invitations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create a dummy action.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

  return Ok(());

}

/// Verifies that the server returns a 403 status code when the user lacks permissions and is authenticated.
#[tokio::test]
async fn verify_permission_when_listing_membership_invitations() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;
  initialize_predefined_configurations(&test_environment.database_pool).await?;

  // Create the user and the session.
  let user = test_environment.create_random_user().await?;
  let session = test_environment.create_random_session(Some(&user.id)).await?;
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let session_token = session.generate_json_web_token(&json_web_token_private_key).await?;

  // Create a dummy action.
  let dummy_group = test_environment.create_random_group().await?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.get(&format!("/groups/{}/membership-invitations", &dummy_group.id))
    .add_cookie(Cookie::new("sessionToken", format!("Bearer {}", session_token)))
    .await;
  
  assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

  return Ok(());

}