use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, DefaultFieldValue, FieldValueType, InitialDefaultFieldValueProperties};

fn assert_fields_are_equal(default_field_value_1: &DefaultFieldValue, default_field_value_2: &DefaultFieldValue) {

  assert_eq!(default_field_value_1.id, default_field_value_2.id);
  assert_eq!(default_field_value_1.field_id, default_field_value_2.field_id);
  assert_eq!(default_field_value_1.value_type, default_field_value_2.value_type);
  assert_eq!(default_field_value_1.text_value, default_field_value_2.text_value);
  assert_eq!(default_field_value_1.number_value, default_field_value_2.number_value);
  assert_eq!(default_field_value_1.boolean_value, default_field_value_2.boolean_value);
  assert_eq!(default_field_value_1.timestamp_value, default_field_value_2.timestamp_value);
  assert_eq!(default_field_value_1.stakeholder_type, default_field_value_2.stakeholder_type);
  assert_eq!(default_field_value_1.stakeholder_user_id, default_field_value_2.stakeholder_user_id);
  assert_eq!(default_field_value_1.stakeholder_group_id, default_field_value_2.stakeholder_group_id);
  assert_eq!(default_field_value_1.stakeholder_app_id, default_field_value_2.stakeholder_app_id);

}

fn assert_field_is_equal_to_initial_properties(field_choice: &DefaultFieldValue, initial_properties: &InitialDefaultFieldValueProperties) {

  assert_eq!(field_choice.field_id, initial_properties.field_id);
  assert_eq!(field_choice.value_type, initial_properties.value_type);
  assert_eq!(field_choice.text_value, initial_properties.text_value);
  assert_eq!(field_choice.number_value, initial_properties.number_value);
  assert_eq!(field_choice.boolean_value, initial_properties.boolean_value);
  assert_eq!(field_choice.timestamp_value, initial_properties.timestamp_value);
  assert_eq!(field_choice.stakeholder_type, initial_properties.stakeholder_type);
  assert_eq!(field_choice.stakeholder_user_id, initial_properties.stakeholder_user_id);
  assert_eq!(field_choice.stakeholder_group_id, initial_properties.stakeholder_group_id);
  assert_eq!(field_choice.stakeholder_app_id, initial_properties.stakeholder_app_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<DefaultFieldValue> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_default_field_value().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = DefaultFieldValue::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let field = test_environment.create_random_field().await?;
  let field_properties = InitialDefaultFieldValueProperties {
    field_id: field.id,
    value_type: FieldValueType::Text,
    text_value: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let field_choice = DefaultFieldValue::create(&field_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_field_is_equal_to_initial_properties(&field_choice, &field_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_field_choice = test_environment.create_random_default_field_value().await?;
  
  created_field_choice.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match DefaultFieldValue::get_by_id(&created_field_choice.id, &test_environment.database_pool).await {

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

  let created_field_choice = test_environment.create_random_default_field_value().await?;
  let retrieved_resource = DefaultFieldValue::get_by_id(&created_field_choice.id, &test_environment.database_pool).await?;
  assert_fields_are_equal(&created_field_choice, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut fields: Vec<DefaultFieldValue> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field_choice = test_environment.create_random_default_field_value().await?;
    fields.push(field_choice);

  }

  let retrieved_resources = DefaultFieldValue::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<DefaultFieldValue> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_default_field_value().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = DefaultFieldValue::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&DefaultFieldValue> = created_resources.iter().filter(|field_choice| field_choice.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_fields_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<DefaultFieldValue> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field_choice = test_environment.create_random_default_field_value().await?;
    created_resources.push(field_choice);

  }

  let retrieved_resources = DefaultFieldValue::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_field_choice = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_fields_are_equal(created_field_choice, retrieved_resource);

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
  let mut current_resources = DefaultFieldValue::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let field_choice = test_environment.create_random_default_field_value().await?;
      current_resources.push(field_choice);

    }

  }

  // Get the "slashstep.fields.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_fields_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.fields.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_default_field_value = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_fields_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::DefaultFieldValue,
      scoped_default_field_value_id: Some(scoped_default_field_value.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_default_field_value.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = DefaultFieldValue::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_fields_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
