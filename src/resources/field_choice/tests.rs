use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, field::Field, field_choice::{DEFAULT_RESOURCE_LIST_LIMIT, FieldChoice, FieldChoiceType, InitialFieldChoiceProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_fields_are_equal(field_1: &FieldChoice, field_2: &FieldChoice) {

  assert_eq!(field_1.id, field_2.id);
  assert_eq!(field_1.field_id, field_2.field_id);
  assert_eq!(field_1.description, field_2.description);
  assert_eq!(field_1.value_type, field_2.value_type);
  assert_eq!(field_1.text_value, field_2.text_value);
  assert_eq!(field_1.number_value, field_2.number_value);
  assert_eq!(field_1.timestamp_value, field_2.timestamp_value);

}

fn assert_field_is_equal_to_initial_properties(field_choice: &FieldChoice, initial_properties: &InitialFieldChoiceProperties) {

  assert_eq!(field_choice.field_id, initial_properties.field_id);
  assert_eq!(field_choice.description, initial_properties.description);
  assert_eq!(field_choice.value_type, initial_properties.value_type);
  assert_eq!(field_choice.text_value, initial_properties.text_value);
  assert_eq!(field_choice.number_value, initial_properties.number_value);
  assert_eq!(field_choice.timestamp_value, initial_properties.timestamp_value);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_FIELD_CHOICE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_field_choices: Vec<FieldChoice> = Vec::new();
  for _ in 0..MAXIMUM_FIELD_CHOICE_COUNT {

    let field_choice = test_environment.create_random_field_choice(None).await?;
    created_field_choices.push(field_choice);

  }

  let retrieved_field_count = FieldChoice::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_field_count, MAXIMUM_FIELD_CHOICE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let field = test_environment.create_random_field().await?;
  let field_properties = InitialFieldChoiceProperties {
    field_id: field.id,
    description: Some(Uuid::now_v7().to_string()),
    value_type: FieldChoiceType::Text,
    text_value: Some(Uuid::now_v7().to_string()),
    ..Default::default()
  };
  let field_choice = FieldChoice::create(&field_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_field_is_equal_to_initial_properties(&field_choice, &field_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_field_choice = test_environment.create_random_field_choice(None).await?;
  
  created_field_choice.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match FieldChoice::get_by_id(&created_field_choice.id, &test_environment.database_pool).await {

    Ok(_) => panic!("Expected an app authorization not found error."),

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

  let created_field_choice = test_environment.create_random_field_choice(None).await?;
  let retrieved_field = FieldChoice::get_by_id(&created_field_choice.id, &test_environment.database_pool).await?;
  assert_fields_are_equal(&created_field_choice, &retrieved_field);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_FIELD_CHOICE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut fields: Vec<FieldChoice> = Vec::new();
  for _ in 0..MAXIMUM_FIELD_CHOICE_COUNT {

    let field_choice = test_environment.create_random_field_choice(None).await?;
    fields.push(field_choice);

  }

  let retrieved_fields = FieldChoice::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_fields.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_field_choices: Vec<FieldChoice> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field_choice = test_environment.create_random_field_choice(None).await?;
    created_field_choices.push(field_choice);

  }

  let query = format!("id = \"{}\"", created_field_choices[0].id);
  let retrieved_fields = FieldChoice::list(&query, &test_environment.database_pool, None).await?;

  let created_field_choices_with_specific_id: Vec<&FieldChoice> = created_field_choices.iter().filter(|field_choice| field_choice.id == created_field_choices[0].id).collect();
  assert_eq!(created_field_choices_with_specific_id.len(), retrieved_fields.len());
  for i in 0..created_field_choices_with_specific_id.len() {

    let created_field_choice = &created_field_choices_with_specific_id[i];
    let retrieved_field = &retrieved_fields[i];

    assert_fields_are_equal(created_field_choice, retrieved_field);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_field_choices: Vec<FieldChoice> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let field_choice = test_environment.create_random_field_choice(None).await?;
    created_field_choices.push(field_choice);

  }

  let retrieved_fields = FieldChoice::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_field_choices.len(), retrieved_fields.len());
  for i in 0..created_field_choices.len() {

    let created_field_choice = &created_field_choices[i];
    let retrieved_field = &retrieved_fields[i];

    assert_fields_are_equal(created_field_choice, retrieved_field);

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
  let mut current_fields = FieldChoice::list("", &test_environment.database_pool, None).await?;
  if current_fields.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_fields.len() as i32;
    for _ in 0..remaining_action_count {

      let field_choice = test_environment.create_random_field_choice(None).await?;
      current_fields.push(field_choice);

    }

  }

  // Get the "slashstep.fields.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_fields_action = Action::get_by_name("slashstep.fieldChoices.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.fields.get" action to the user for half of the actions.
  let allowed_action_count = current_fields.len() / 2;
  let mut allowed_fields = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_field_choice = &current_fields[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_fields_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::FieldChoice,
      scoped_field_choice_id: Some(scoped_field_choice.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_fields.push(scoped_field_choice.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_fields = FieldChoice::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_fields.len(), retrieved_fields.len());
  for allowed_field in allowed_fields {

    let retrieved_field = &retrieved_fields.iter().find(|action| action.id == allowed_field.id).unwrap();

    assert_fields_are_equal(&allowed_field, retrieved_field);

  }

  return Ok(());

}
