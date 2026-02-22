use std::net::{IpAddr, Ipv4Addr};
use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    },
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, User, InitialUserProperties};

fn assert_server_log_entries_are_equal(user_1: &User, user_2: &User) {

  assert_eq!(user_1.id, user_2.id);
  assert_eq!(user_1.username, user_2.username);
  assert_eq!(user_1.display_name, user_2.display_name);
  assert_eq!(user_1.ip_address, user_2.ip_address);
  assert_eq!(user_1.is_anonymous, user_2.is_anonymous);

}

fn assert_user_is_equal_to_initial_properties(user: &User, initial_properties: &InitialUserProperties) {

  assert_eq!(user.username, initial_properties.username);
  assert_eq!(user.display_name, initial_properties.display_name);
  assert_eq!(user.ip_address, initial_properties.ip_address);
  assert_eq!(user.is_anonymous, initial_properties.is_anonymous);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<User> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_user().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = User::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let user_properties = InitialUserProperties {
    username: None,
    hashed_password: None,
    is_anonymous: true,
    ip_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
    display_name: None,
  };
  let user = User::create(&user_properties, &test_environment.database_pool).await?;
  assert_user_is_equal_to_initial_properties(&user, &user_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_user = test_environment.create_random_user().await?;
  
  created_user.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match User::get_by_id(&created_user.id, &test_environment.database_pool).await {

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

  let created_user = test_environment.create_random_user().await?;
  let retrieved_resource = User::get_by_id(&created_user.id, &test_environment.database_pool).await?;
  assert_server_log_entries_are_equal(&created_user, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut server_log_entries: Vec<User> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let user = test_environment.create_random_user().await?;
    server_log_entries.push(user);

  }

  let retrieved_resources = User::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<User> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_user().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = User::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&User> = created_resources.iter().filter(|user| user.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_server_log_entries_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<User> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let user = test_environment.create_random_user().await?;
    created_resources.push(user);

  }

  let retrieved_resources = User::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_user = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_server_log_entries_are_equal(created_user, retrieved_resource);

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
  let mut current_resources = User::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let user = test_environment.create_random_user().await?;
      current_resources.push(user);

    }

  }

  // Get the "slashstep.server_log_entries.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_server_log_entries_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.server_log_entries.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_user = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_server_log_entries_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::User,
      scoped_user_id: Some(scoped_user.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_user);

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = User::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_server_log_entries_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
