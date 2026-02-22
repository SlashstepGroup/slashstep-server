use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, field::{DEFAULT_RESOURCE_LIST_LIMIT, Field, FieldParentResourceType, FieldValueType, InitialFieldProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_fields_are_equal(field_1: &Field, field_2: &Field) {

  assert_eq!(field_1.id, field_2.id);
  assert_eq!(field_1.name, field_2.name);
  assert_eq!(field_1.display_name, field_2.display_name);
  assert_eq!(field_1.description, field_2.description);
  assert_eq!(field_1.is_required, field_2.is_required);
  assert_eq!(field_1.field_value_type, field_2.field_value_type);
  assert_eq!(field_1.minimum_value, field_2.minimum_value);
  assert_eq!(field_1.maximum_value, field_2.maximum_value);
  assert_eq!(field_1.minimum_choice_count, field_2.minimum_choice_count);
  assert_eq!(field_1.maximum_choice_count, field_2.maximum_choice_count);
  assert_eq!(field_1.parent_resource_type, field_2.parent_resource_type);
  assert_eq!(field_1.parent_project_id, field_2.parent_project_id);
  assert_eq!(field_1.parent_workspace_id, field_2.parent_workspace_id);

}

fn assert_field_is_equal_to_initial_properties(field: &Field, initial_properties: &InitialFieldProperties) {

  assert_eq!(field.name, initial_properties.name);
  assert_eq!(field.display_name, initial_properties.display_name);
  assert_eq!(field.description, initial_properties.description);
  assert_eq!(field.is_required, initial_properties.is_required);
  assert_eq!(field.field_value_type, initial_properties.field_value_type);
  assert_eq!(field.minimum_value, initial_properties.minimum_value);
  assert_eq!(field.maximum_value, initial_properties.maximum_value);
  assert_eq!(field.minimum_choice_count, initial_properties.minimum_choice_count);
  assert_eq!(field.maximum_choice_count, initial_properties.maximum_choice_count);
  assert_eq!(field.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(field.parent_project_id, initial_properties.parent_project_id);
  assert_eq!(field.parent_workspace_id, initial_properties.parent_workspace_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_FIELD_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_fields: Vec<Field> = Vec::new();
  for _ in 0..MAXIMUM_FIELD_COUNT {

    let field = test_environment.create_random_field().await?;
    created_fields.push(field);

  }

  let retrieved_field_count = Field::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_field_count, MAXIMUM_FIELD_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let workspace = test_environment.create_random_workspace().await?;
  let field_properties = InitialFieldProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string(),
    is_required: true,
    field_value_type: FieldValueType::Text,
    parent_resource_type: FieldParentResourceType::Workspace,
    parent_workspace_id: Some(workspace.id),
    ..Default::default()
  };
  let field = Field::create(&field_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_field_is_equal_to_initial_properties(&field, &field_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_field = test_environment.create_random_field().await?;
  
  created_field.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Field::get_by_id(&created_field.id, &test_environment.database_pool).await {

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

  let created_field = test_environment.create_random_field().await?;
  let retrieved_field = Field::get_by_id(&created_field.id, &test_environment.database_pool).await?;
  assert_fields_are_equal(&created_field, &retrieved_field);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_FIELD_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut fields: Vec<Field> = Vec::new();
  for _ in 0..MAXIMUM_FIELD_COUNT {

    let field = test_environment.create_random_field().await?;
    fields.push(field);

  }

  let retrieved_fields = Field::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_fields.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_fields: Vec<Field> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field = test_environment.create_random_field().await?;
    created_fields.push(field);

  }

  let query = format!("id = \"{}\"", created_fields[0].id);
  let retrieved_fields = Field::list(&query, &test_environment.database_pool, None).await?;

  let created_fields_with_specific_id: Vec<&Field> = created_fields.iter().filter(|field| field.id == created_fields[0].id).collect();
  assert_eq!(created_fields_with_specific_id.len(), retrieved_fields.len());
  for i in 0..created_fields_with_specific_id.len() {

    let created_field = &created_fields_with_specific_id[i];
    let retrieved_field = &retrieved_fields[i];

    assert_fields_are_equal(created_field, retrieved_field);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_fields: Vec<Field> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field = test_environment.create_random_field().await?;
    created_fields.push(field);

  }

  let retrieved_fields = Field::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_fields.len(), retrieved_fields.len());
  for i in 0..created_fields.len() {

    let created_field = &created_fields[i];
    let retrieved_field = &retrieved_fields[i];

    assert_fields_are_equal(created_field, retrieved_field);

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

  const MINIMUM_ACTION_COUNT: i32 = 2;
  let mut current_fields = Field::list("", &test_environment.database_pool, None).await?;
  if current_fields.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_fields.len() as i32;
    for _ in 0..remaining_action_count {

      let field = test_environment.create_random_field().await?;
      current_fields.push(field);

    }

  }

  // Get the "slashstep.fields.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_fields_action = Action::get_by_name("slashstep.fields.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.fields.get" action to the user for half of the actions.
  let allowed_action_count = current_fields.len() / 2;
  let mut allowed_fields = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_field = &current_fields[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_fields_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Field,
      scoped_field_id: Some(scoped_field.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_fields.push(scoped_field.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_fields = Field::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_fields.len(), retrieved_fields.len());
  for allowed_field in allowed_fields {

    let retrieved_field = &retrieved_fields.iter().find(|action| action.id == allowed_field.id).unwrap();

    assert_fields_are_equal(&allowed_field, retrieved_field);

  }

  return Ok(());

}
