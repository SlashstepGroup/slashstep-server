use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, configuration::ConfigurationValueType
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Configuration, InitialConfigurationProperties};

fn assert_configurations_are_equal(configuration_1: &Configuration, configuration_2: &Configuration) {

  assert_eq!(configuration_1.id, configuration_2.id);
  assert_eq!(configuration_1.name, configuration_2.name);
  assert_eq!(configuration_1.value_type, configuration_2.value_type);
  assert_eq!(configuration_1.text_value, configuration_2.text_value);
  assert_eq!(configuration_1.integer_value, configuration_2.integer_value);
  assert_eq!(configuration_1.decimal_value, configuration_2.decimal_value);
  assert_eq!(configuration_1.boolean_value, configuration_2.boolean_value);

}

fn assert_configuration_is_equal_to_initial_properties(configuration: &Configuration, initial_properties: &InitialConfigurationProperties) {

  assert_eq!(configuration.name, initial_properties.name);
  assert_eq!(configuration.value_type, initial_properties.value_type);
  assert_eq!(configuration.text_value, initial_properties.text_value);
  assert_eq!(configuration.integer_value, initial_properties.integer_value);
  assert_eq!(configuration.decimal_value, initial_properties.decimal_value);
  assert_eq!(configuration.boolean_value, initial_properties.boolean_value);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Configuration> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_configuration().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Configuration::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the configuration.
  let configuration_properties = InitialConfigurationProperties {
    name: Uuid::now_v7().to_string(),
    value_type: ConfigurationValueType::Text,
    text_value: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let configuration = Configuration::create(&configuration_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_configuration_is_equal_to_initial_properties(&configuration, &configuration_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_configuration = test_environment.create_random_configuration().await?;
  
  created_configuration.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Configuration::get_by_id(&created_configuration.id, &test_environment.database_pool).await {

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

  let created_configuration = test_environment.create_random_configuration().await?;
  let retrieved_resource = Configuration::get_by_id(&created_configuration.id, &test_environment.database_pool).await?;
  assert_configurations_are_equal(&created_configuration, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut configurations: Vec<Configuration> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let configuration = test_environment.create_random_configuration().await?;
    configurations.push(configuration);

  }

  let retrieved_resources = Configuration::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Configuration> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_configuration().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Configuration::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&Configuration> = created_resources.iter().filter(|configuration| configuration.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_configurations_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Configuration> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let configuration = test_environment.create_random_configuration().await?;
    created_resources.push(configuration);

  }

  let retrieved_resources = Configuration::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_configuration = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_configurations_are_equal(created_configuration, retrieved_resource);

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
  let mut current_resources = Configuration::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let configuration = test_environment.create_random_configuration().await?;
      current_resources.push(configuration);

    }

  }

  // Get the "slashstep.configurations.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_configurations_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.configurations.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_configuration = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_configurations_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Configuration,
      scoped_configuration_id: Some(scoped_configuration.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_configuration.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = Configuration::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_configurations_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
