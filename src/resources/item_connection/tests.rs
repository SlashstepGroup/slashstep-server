use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, ItemConnection, InitialItemConnectionProperties};

fn assert_item_connections_are_equal(item_connection_1: &ItemConnection, item_connection_2: &ItemConnection) {

  assert_eq!(item_connection_1.id, item_connection_2.id);
  assert_eq!(item_connection_1.item_connection_type_id, item_connection_2.item_connection_type_id);
  assert_eq!(item_connection_1.inward_item_id, item_connection_2.inward_item_id);
  assert_eq!(item_connection_1.outward_item_id, item_connection_2.outward_item_id);

}

fn assert_item_connection_is_equal_to_initial_properties(item_connection: &ItemConnection, initial_properties: &InitialItemConnectionProperties) {

  assert_eq!(item_connection.item_connection_type_id, initial_properties.item_connection_type_id);
  assert_eq!(item_connection.inward_item_id, initial_properties.inward_item_id);
  assert_eq!(item_connection.outward_item_id, initial_properties.outward_item_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<ItemConnection> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_connection().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = ItemConnection::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let item_connection_type = test_environment.create_random_item_connection_type().await?;
  let inward_item = test_environment.create_random_item().await?;
  let outward_item = test_environment.create_random_item().await?;
  let item_connection_properties = InitialItemConnectionProperties {
    item_connection_type_id: item_connection_type.id,
    inward_item_id: inward_item.id,
    outward_item_id: outward_item.id
  };
  let item_connection = ItemConnection::create(&item_connection_properties, &test_environment.database_pool).await?;
  assert_item_connection_is_equal_to_initial_properties(&item_connection, &item_connection_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_item_connection = test_environment.create_random_item_connection().await?;
  
  created_item_connection.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match ItemConnection::get_by_id(&created_item_connection.id, &test_environment.database_pool).await {

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

  let created_item_connection = test_environment.create_random_item_connection().await?;
  let retrieved_resource = ItemConnection::get_by_id(&created_item_connection.id, &test_environment.database_pool).await?;
  assert_item_connections_are_equal(&created_item_connection, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut item_connections: Vec<ItemConnection> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_connection = test_environment.create_random_item_connection().await?;
    item_connections.push(item_connection);

  }

  let retrieved_resources = ItemConnection::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<ItemConnection> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_item_connection().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = ItemConnection::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&ItemConnection> = created_resources.iter().filter(|item_connection| item_connection.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_connections_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<ItemConnection> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let item_connection = test_environment.create_random_item_connection().await?;
    created_resources.push(item_connection);

  }

  let retrieved_resources = ItemConnection::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_item_connection = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_item_connections_are_equal(created_item_connection, retrieved_resource);

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
  let mut current_resources = ItemConnection::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let item_connection = test_environment.create_random_item_connection().await?;
      current_resources.push(item_connection);

    }

  }

  // Get the "slashstep.item_connections.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_item_connections_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.item_connections.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_item_connection = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_item_connections_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::ItemConnection,
      scoped_item_connection_id: Some(scoped_item_connection.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_item_connection.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = ItemConnection::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_item_connections_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
