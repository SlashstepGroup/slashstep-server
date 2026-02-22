use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, membership::MembershipParentResourceType
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Membership, InitialMembershipProperties};

fn assert_membership_types_are_equal(membership_1: &Membership, membership_2: &Membership) {

  assert_eq!(membership_1.id, membership_2.id);
  assert_eq!(membership_1.parent_resource_type, membership_2.parent_resource_type);
  assert_eq!(membership_1.parent_group_id, membership_2.parent_group_id);
  assert_eq!(membership_1.parent_role_id, membership_2.parent_role_id);
  assert_eq!(membership_1.principal_type, membership_2.principal_type);
  assert_eq!(membership_1.principal_user_id, membership_2.principal_user_id);
  assert_eq!(membership_1.principal_group_id, membership_2.principal_group_id);
  assert_eq!(membership_1.principal_app_id, membership_2.principal_app_id);

}

fn assert_membership_is_equal_to_initial_properties(membership: &Membership, initial_properties: &InitialMembershipProperties) {

  assert_eq!(membership.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(membership.parent_group_id, initial_properties.parent_group_id);
  assert_eq!(membership.parent_role_id, initial_properties.parent_role_id);
  assert_eq!(membership.principal_type, initial_properties.principal_type);
  assert_eq!(membership.principal_user_id, initial_properties.principal_user_id);
  assert_eq!(membership.principal_group_id, initial_properties.principal_group_id);
  assert_eq!(membership.principal_app_id, initial_properties.principal_app_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Membership> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_membership().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Membership::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let group = test_environment.create_random_group().await?;
  let membership_properties = InitialMembershipProperties {
    parent_resource_type: MembershipParentResourceType::Group,
    parent_group_id: Some(group.id),
    ..Default::default()
  };
  let membership = Membership::create(&membership_properties, &test_environment.database_pool).await?;
  assert_membership_is_equal_to_initial_properties(&membership, &membership_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_membership = test_environment.create_random_membership().await?;
  
  created_membership.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Membership::get_by_id(&created_membership.id, &test_environment.database_pool).await {

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

  let created_membership = test_environment.create_random_membership().await?;
  let retrieved_resource = Membership::get_by_id(&created_membership.id, &test_environment.database_pool).await?;
  assert_membership_types_are_equal(&created_membership, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut membership_types: Vec<Membership> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let membership = test_environment.create_random_membership().await?;
    membership_types.push(membership);

  }

  let retrieved_resources = Membership::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Membership> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_membership().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Membership::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&Membership> = created_resources.iter().filter(|membership| membership.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_membership_types_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Membership> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let membership = test_environment.create_random_membership().await?;
    created_resources.push(membership);

  }

  let retrieved_resources = Membership::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_membership = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_membership_types_are_equal(created_membership, retrieved_resource);

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
  let mut current_resources = Membership::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let membership = test_environment.create_random_membership().await?;
      current_resources.push(membership);

    }

  }

  // Get the "slashstep.membership_types.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_membership_types_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.membership_types.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_membership = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_membership_types_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Membership,
      scoped_membership_id: Some(scoped_membership.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_membership.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = Membership::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_membership_types_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
