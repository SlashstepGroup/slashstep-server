use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    ResourceError, access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, status::StatusType,
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Status, InitialStatusProperties};

fn assert_statuses_are_equal(status_1: &Status, status_2: &Status) {

  assert_eq!(status_1.id, status_2.id);
  assert_eq!(status_1.display_name, status_2.display_name);
  assert_eq!(status_1.status_type, status_2.status_type);
  assert_eq!(status_1.decimal_color, status_2.decimal_color);
  assert_eq!(status_1.description, status_2.description);
  assert_eq!(status_1.next_status_id, status_2.next_status_id);
  assert_eq!(status_1.parent_project_id, status_2.parent_project_id);

}

fn assert_status_is_equal_to_initial_properties(status: &Status, initial_properties: &InitialStatusProperties) {

  assert_eq!(status.display_name, initial_properties.display_name);
  assert_eq!(status.status_type, initial_properties.status_type);
  assert_eq!(status.decimal_color, initial_properties.decimal_color);
  assert_eq!(status.description, initial_properties.description);
  assert_eq!(status.next_status_id, initial_properties.next_status_id);
  assert_eq!(status.parent_project_id, initial_properties.parent_project_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Status> = Vec::new();
  let project_id = test_environment.create_random_project().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_status(Some(&project_id)).await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Status::count("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let project_id = test_environment.create_random_project().await?.id;
  let status_properties = InitialStatusProperties {
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    status_type: StatusType::ToDo,
    parent_project_id: project_id,
    ..Default::default()
  };

  let status = Status::create(&status_properties, &test_environment.database_pool).await?;
  assert_status_is_equal_to_initial_properties(&status, &status_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let created_status = test_environment.create_random_status(None).await?;
  
  created_status.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Status::get_by_id(&created_status.id, &test_environment.database_pool).await {

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

  let created_status = test_environment.create_random_status(None).await?;
  let retrieved_resource = Status::get_by_id(&created_status.id, &test_environment.database_pool).await?;
  assert_statuses_are_equal(&created_status, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut statuses: Vec<Status> = Vec::new();
  let project_id = test_environment.create_random_project().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let status = test_environment.create_random_status(Some(&project_id)).await?;
    statuses.push(status);

  }

  let retrieved_resources = Status::list("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Status> = Vec::new();
  let project_id = test_environment.create_random_project().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_status(Some(&project_id)).await?;
    created_resources.push(resource);

  }

  // The next_status_id of the created resources are expected to change,
  // so we need to get the resources again to ensure we have the correct next_status_ids.
  for index in 0..created_resources.len() {

    created_resources[index] = Status::get_by_id(&created_resources[index].id, &test_environment.database_pool).await?;

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Status::list(&query, &test_environment.database_pool, None, None).await?;

  let created_resources_with_specific_id: Vec<&Status> = created_resources.iter().filter(|status| status.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_statuses_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Status> = Vec::new();
  let project_id = test_environment.create_random_project().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let status = test_environment.create_random_status(Some(&project_id)).await?;
    created_resources.push(status);

  }

  // The next_status_id of the created resources are expected to change,
  // so we need to get the resources again to ensure we have the correct next_status_ids.
  for index in 0..created_resources.len() {

    created_resources[index] = Status::get_by_id(&created_resources[index].id, &test_environment.database_pool).await?;

  }

  let retrieved_resources = Status::list("", &test_environment.database_pool, None, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for created_resource in created_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == created_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_statuses_are_equal(&created_resource, retrieved_resource);

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
  let mut current_resources = Status::list("", &test_environment.database_pool, None, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let project_id = test_environment.create_random_project().await?.id;
    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let status = test_environment.create_random_status(Some(&project_id)).await?;
      current_resources.push(status);

    }

    // The next_status_id of the created resources are expected to change,
    // so we need to get the resources again to ensure we have the correct next_status_ids.
    for index in 0..current_resources.len() {

      current_resources[index] = Status::get_by_id(&current_resources[index].id, &test_environment.database_pool).await?;

    }

  }

  // Get the "statuses.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_statuses_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "statuses.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_status = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_statuses_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::ResourceType::Status,
      scoped_status_id: Some(scoped_status.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_status.clone());

  }

  // Make sure the user only sees the allowed actions.
  let retrieved_resources = Status::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_statuses_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
