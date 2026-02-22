use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, item_connection_type::ItemConnectionTypeParentResourceType
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, ItemConnectionType, InitialItemConnectionTypeProperties};

fn assert_item_connection_type_types_are_equal(item_connection_type_1: &ItemConnectionType, item_connection_type_2: &ItemConnectionType) {

  assert_eq!(item_connection_type_1.id, item_connection_type_2.id);
  assert_eq!(item_connection_type_1.display_name, item_connection_type_2.display_name);
  assert_eq!(item_connection_type_1.inward_description, item_connection_type_2.inward_description);
  assert_eq!(item_connection_type_1.outward_description, item_connection_type_2.outward_description);
  assert_eq!(item_connection_type_1.parent_resource_type, item_connection_type_2.parent_resource_type);
  assert_eq!(item_connection_type_1.parent_project_id, item_connection_type_2.parent_project_id);

}

fn assert_item_connection_type_is_equal_to_initial_properties(item_connection_type: &ItemConnectionType, initial_properties: &InitialItemConnectionTypeProperties) {

  assert_eq!(item_connection_type.display_name, initial_properties.display_name);
  assert_eq!(item_connection_type.inward_description, initial_properties.inward_description);
  assert_eq!(item_connection_type.outward_description, initial_properties.outward_description);
  assert_eq!(item_connection_type.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(item_connection_type.parent_project_id, initial_properties.parent_project_id);
  assert_eq!(item_connection_type.parent_workspace_id, initial_properties.parent_workspace_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<ItemConnectionType> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_connection_type().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = ItemConnectionType::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let parent_workspace = test_environment.create_random_workspace().await?;
  let item_connection_type_properties = InitialItemConnectionTypeProperties {
    display_name: Uuid::now_v7().to_string(),
    inward_description: Uuid::now_v7().to_string(),
    outward_description: Uuid::now_v7().to_string(),
    parent_resource_type: ItemConnectionTypeParentResourceType::Workspace,
    parent_workspace_id: Some(parent_workspace.id),
    ..Default::default()
  };
  let item_connection_type = ItemConnectionType::create(&item_connection_type_properties, &test_environment.database_pool).await?;
  assert_item_connection_type_is_equal_to_initial_properties(&item_connection_type, &item_connection_type_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_item_connection_type = test_environment.create_random_item_connection_type().await?;
  
  created_item_connection_type.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match ItemConnectionType::get_by_id(&created_item_connection_type.id, &test_environment.database_pool).await {

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

  let created_item_connection_type = test_environment.create_random_item_connection_type().await?;
  let retrieved_resource = ItemConnectionType::get_by_id(&created_item_connection_type.id, &test_environment.database_pool).await?;
  assert_item_connection_type_types_are_equal(&created_item_connection_type, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut item_connection_type_types: Vec<ItemConnectionType> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_connection_type = test_environment.create_random_item_connection_type().await?;
    item_connection_type_types.push(item_connection_type);

  }

  let retrieved_resources = ItemConnectionType::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<ItemConnectionType> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_connection_type().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = ItemConnectionType::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&ItemConnectionType> = created_resources.iter().filter(|item_connection_type| item_connection_type.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_connection_type_types_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<ItemConnectionType> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_connection_type = test_environment.create_random_item_connection_type().await?;
    created_resources.push(item_connection_type);

  }

  let retrieved_resources = ItemConnectionType::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_item_connection_type = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_connection_type_types_are_equal(created_item_connection_type, retrieved_resource);

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
  let mut current_resources = ItemConnectionType::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let item_connection_type = test_environment.create_random_item_connection_type().await?;
      current_resources.push(item_connection_type);

    }

  }

  // Get the "slashstep.item_connection_type_types.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_item_connection_type_types_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.item_connection_type_types.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_item_connection_type = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_item_connection_type_types_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::ItemConnectionType,
      scoped_item_connection_type_id: Some(scoped_item_connection_type.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_item_connection_type.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = ItemConnectionType::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_item_connection_type_types_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
