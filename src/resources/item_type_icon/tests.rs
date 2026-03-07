use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    ResourceError, access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, item_type_icon::ItemTypeIconParentResourceType,
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, ItemTypeIcon, InitialItemTypeIconProperties};

fn assert_item_type_icons_are_equal(item_type_icon_1: &ItemTypeIcon, item_type_icon_2: &ItemTypeIcon) {

  assert_eq!(item_type_icon_1.id, item_type_icon_2.id);
  assert_eq!(item_type_icon_1.display_name, item_type_icon_2.display_name);
  assert_eq!(item_type_icon_1.parent_resource_type, item_type_icon_2.parent_resource_type);
  assert_eq!(item_type_icon_1.parent_project_id, item_type_icon_2.parent_project_id);
  assert_eq!(item_type_icon_1.local_file_path, item_type_icon_2.local_file_path);

}

fn assert_item_type_icon_is_equal_to_initial_properties(item_type_icon: &ItemTypeIcon, initial_properties: &InitialItemTypeIconProperties) {

  assert_eq!(item_type_icon.display_name, initial_properties.display_name);
  assert_eq!(item_type_icon.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(item_type_icon.parent_project_id, initial_properties.parent_project_id);
  assert_eq!(item_type_icon.local_file_path, initial_properties.local_file_path);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<ItemTypeIcon> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_type_icon(None).await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = ItemTypeIcon::count("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let item_type_icon_properties = InitialItemTypeIconProperties {
    display_name: Uuid::now_v7().to_string(),
    parent_resource_type: ItemTypeIconParentResourceType::Server,
    parent_project_id: None,
    local_file_path: "./src/icons/default-item-type-icon.svg".to_string()
  };

  let item_type_icon = ItemTypeIcon::create(&item_type_icon_properties, &test_environment.database_pool).await?;
  assert_item_type_icon_is_equal_to_initial_properties(&item_type_icon, &item_type_icon_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_item_type_icon = test_environment.create_random_item_type_icon(None).await?;
  
  created_item_type_icon.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match ItemTypeIcon::get_by_id(&created_item_type_icon.id, &test_environment.database_pool).await {

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

  let created_item_type_icon = test_environment.create_random_item_type_icon(None).await?;
  let retrieved_resource = ItemTypeIcon::get_by_id(&created_item_type_icon.id, &test_environment.database_pool).await?;
  assert_item_type_icons_are_equal(&created_item_type_icon, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut item_type_icons: Vec<ItemTypeIcon> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_type_icon = test_environment.create_random_item_type_icon(None).await?;
    item_type_icons.push(item_type_icon);

  }

  let retrieved_resources = ItemTypeIcon::list("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<ItemTypeIcon> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_type_icon(None).await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = ItemTypeIcon::list(&query, &test_environment.database_pool, None, None).await?;

  let created_resources_with_specific_id: Vec<&ItemTypeIcon> = created_resources.iter().filter(|item_type_icon| item_type_icon.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_type_icons_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<ItemTypeIcon> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_type_icon = test_environment.create_random_item_type_icon(None).await?;
    created_resources.push(item_type_icon);

  }

  let retrieved_resources = ItemTypeIcon::list("", &test_environment.database_pool, None, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_item_type_icon = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_type_icons_are_equal(created_item_type_icon, retrieved_resource);

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
  let mut current_resources = ItemTypeIcon::list("", &test_environment.database_pool, None, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let item_type_icon = test_environment.create_random_item_type_icon(None).await?;
      current_resources.push(item_type_icon);

    }

  }

  // Get the "item_type_icons.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_item_type_icons_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "item_type_icons.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_item_type_icon = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_item_type_icons_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::ResourceType::ItemTypeIcon,
      scoped_item_type_icon_id: Some(scoped_item_type_icon.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_item_type_icon.clone());

  }

  // Make sure the user only sees the allowed actions.
  let retrieved_resources = ItemTypeIcon::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_item_type_icons_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
