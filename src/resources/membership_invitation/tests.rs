use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, membership::MembershipParentResourceType,
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, MembershipInvitation, InitialMembershipInvitationProperties};

fn assert_membership_invitation_types_are_equal(membership_invitation_1: &MembershipInvitation, membership_invitation_2: &MembershipInvitation) {

  assert_eq!(membership_invitation_1.id, membership_invitation_2.id);
  assert_eq!(membership_invitation_1.parent_resource_type, membership_invitation_2.parent_resource_type);
  assert_eq!(membership_invitation_1.parent_group_id, membership_invitation_2.parent_group_id);
  assert_eq!(membership_invitation_1.parent_role_id, membership_invitation_2.parent_role_id);
  assert_eq!(membership_invitation_1.invitee_principal_type, membership_invitation_2.invitee_principal_type);
  assert_eq!(membership_invitation_1.invitee_principal_user_id, membership_invitation_2.invitee_principal_user_id);
  assert_eq!(membership_invitation_1.invitee_principal_group_id, membership_invitation_2.invitee_principal_group_id);
  assert_eq!(membership_invitation_1.invitee_principal_app_id, membership_invitation_2.invitee_principal_app_id);
  assert_eq!(membership_invitation_1.inviter_principal_type, membership_invitation_2.inviter_principal_type);
  assert_eq!(membership_invitation_1.inviter_principal_user_id, membership_invitation_2.inviter_principal_user_id);
  assert_eq!(membership_invitation_1.inviter_principal_app_id, membership_invitation_2.inviter_principal_app_id);

}

fn assert_membership_invitation_is_equal_to_initial_properties(membership_invitation: &MembershipInvitation, initial_properties: &InitialMembershipInvitationProperties) {

  assert_eq!(membership_invitation.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(membership_invitation.parent_group_id, initial_properties.parent_group_id);
  assert_eq!(membership_invitation.parent_role_id, initial_properties.parent_role_id);
  assert_eq!(membership_invitation.invitee_principal_type, initial_properties.invitee_principal_type);
  assert_eq!(membership_invitation.invitee_principal_user_id, initial_properties.invitee_principal_user_id);
  assert_eq!(membership_invitation.invitee_principal_group_id, initial_properties.invitee_principal_group_id);
  assert_eq!(membership_invitation.invitee_principal_app_id, initial_properties.invitee_principal_app_id);
  assert_eq!(membership_invitation.inviter_principal_type, initial_properties.inviter_principal_type);
  assert_eq!(membership_invitation.inviter_principal_user_id, initial_properties.inviter_principal_user_id);
  assert_eq!(membership_invitation.inviter_principal_app_id, initial_properties.inviter_principal_app_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<MembershipInvitation> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_membership_invitation().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = MembershipInvitation::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let group = test_environment.create_random_group().await?;
  let membership_invitation_properties = InitialMembershipInvitationProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(group.id),
    ..Default::default()
  };
  let membership_invitation = MembershipInvitation::create(&membership_invitation_properties, &test_environment.database_pool).await?;
  assert_membership_invitation_is_equal_to_initial_properties(&membership_invitation, &membership_invitation_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_membership_invitation = test_environment.create_random_membership_invitation().await?;
  
  created_membership_invitation.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match MembershipInvitation::get_by_id(&created_membership_invitation.id, &test_environment.database_pool).await {

    Ok(_) => panic!("Expected a resource not found error."),

    Err(error) => match error {

      ResourceError::NotFoundError(_) => {},

      error => return Err(TestSlashstepServerError::ResourceError(error))

    }

  };

  return Ok(());

}

#[tokio::test]
async fn initialize_resource_table() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  return Ok(());

}

#[tokio::test]
async fn verify_get_resource_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let created_membership_invitation = test_environment.create_random_membership_invitation().await?;
  let retrieved_resource = MembershipInvitation::get_by_id(&created_membership_invitation.id, &test_environment.database_pool).await?;
  assert_membership_invitation_types_are_equal(&created_membership_invitation, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut membership_invitation_types: Vec<MembershipInvitation> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let membership_invitation = test_environment.create_random_membership_invitation().await?;
    membership_invitation_types.push(membership_invitation);

  }

  let retrieved_resources = MembershipInvitation::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<MembershipInvitation> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_membership_invitation().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = MembershipInvitation::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&MembershipInvitation> = created_resources.iter().filter(|membership_invitation| membership_invitation.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_membership_invitation_types_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<MembershipInvitation> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let membership_invitation = test_environment.create_random_membership_invitation().await?;
    created_resources.push(membership_invitation);

  }

  let retrieved_resources = MembershipInvitation::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_membership_invitation = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_membership_invitation_types_are_equal(created_membership_invitation, retrieved_resource);

  }

  return Ok(());

}

/// Verifies that a list of resources can be retrieved without a query.
#[tokio::test]
async fn verify_list_resources_without_query_and_filter_based_on_requestor_permissions() -> Result<(), TestSlashstepServerError> {

  // Make sure there are at least two actions.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;

  const MINIMUM_RESOURCE_COUNT: i32 = 2;
  let mut current_resources = MembershipInvitation::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let membership_invitation = test_environment.create_random_membership_invitation().await?;
      current_resources.push(membership_invitation);

    }

  }

  // Get the "membership_invitation_types.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_membership_invitation_types_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "membership_invitation_types.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_membership_invitation = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_membership_invitation_types_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::MembershipInvitation,
      scoped_membership_invitation_id: Some(scoped_membership_invitation.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_membership_invitation.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = MembershipInvitation::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_membership_invitation_types_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
