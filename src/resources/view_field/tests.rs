use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties, AccessPolicyPrincipalType}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    },
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, ViewField, InitialViewFieldProperties};

fn assert_view_fields_are_equal(view_field_1: &ViewField, view_field_2: &ViewField) {

  assert_eq!(view_field_1.id, view_field_2.id);
  assert_eq!(view_field_1.parent_view_id, view_field_2.parent_view_id);
  assert_eq!(view_field_1.field_id, view_field_2.field_id);
  assert_eq!(view_field_1.next_view_field_id, view_field_2.next_view_field_id);

}

fn assert_view_field_is_equal_to_initial_properties(view_field: &ViewField, initial_properties: &InitialViewFieldProperties) {

  assert_eq!(view_field.parent_view_id, initial_properties.parent_view_id);
  assert_eq!(view_field.field_id, initial_properties.field_id);
  assert_eq!(view_field.next_view_field_id, initial_properties.next_view_field_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<ViewField> = Vec::new();
  let view_id = test_environment.create_random_view().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_view_field(Some(&view_id), None).await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = ViewField::count("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let parent_view_id = test_environment.create_random_view().await?.id;
  let field_id = test_environment.create_random_field().await?.id;
  let view_field_properties = InitialViewFieldProperties {
    parent_view_id,
    field_id,
    next_view_field_id: None
  };

  let view_field = ViewField::create(&view_field_properties, &test_environment.database_pool).await?;
  assert_view_field_is_equal_to_initial_properties(&view_field, &view_field_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let view_id = test_environment.create_random_view().await?.id;
  let created_view_field = test_environment.create_random_view_field(Some(&view_id), None).await?;
  
  created_view_field.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match ViewField::get_by_id(&created_view_field.id, &test_environment.database_pool).await {

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

  let view_id = test_environment.create_random_view().await?.id;
  let created_view_field = test_environment.create_random_view_field(Some(&view_id), None).await?;
  let retrieved_resource = ViewField::get_by_id(&created_view_field.id, &test_environment.database_pool).await?;
  assert_view_fields_are_equal(&created_view_field, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut view_fields: Vec<ViewField> = Vec::new();
  let view_id = test_environment.create_random_view().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let view_field = test_environment.create_random_view_field(Some(&view_id), None).await?;
    view_fields.push(view_field);

  }

  let retrieved_resources = ViewField::list("", &test_environment.database_pool, None, None).await?;

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
  let mut created_resources: Vec<ViewField> = Vec::new();
  let view_id = test_environment.create_random_view().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_view_field(Some(&view_id), None).await?;
    created_resources.push(resource);

  }

  // The next_view_field_id of the created resources are expected to change,
  // so we need to get the resources again to ensure we have the correct next_view_field_ids.
  for index in 0..created_resources.len() {

    created_resources[index] = ViewField::get_by_id(&created_resources[index].id, &test_environment.database_pool).await?;

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = ViewField::list(&query, &test_environment.database_pool, None, None).await?;

  let created_resources_with_specific_id: Vec<&ViewField> = created_resources.iter().filter(|view_field| view_field.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_view_fields_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<ViewField> = Vec::new();
  let view_id = test_environment.create_random_view().await?.id;
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let view_field = test_environment.create_random_view_field(Some(&view_id), None).await?;
    created_resources.push(view_field);

  }

  // The next_view_field_id of the created resources are expected to change,
  // so we need to get the resources again to ensure we have the correct next_view_field_ids.
  for index in 0..created_resources.len() {

    created_resources[index] = ViewField::get_by_id(&created_resources[index].id, &test_environment.database_pool).await?;

  }

  let retrieved_resources = ViewField::list("", &test_environment.database_pool, None, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for created_resource in created_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == created_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_view_fields_are_equal(&created_resource, retrieved_resource);

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
  let mut current_resources = ViewField::list("", &test_environment.database_pool, None, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let view_id = test_environment.create_random_view().await?.id;
    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let view_field = test_environment.create_random_view_field(Some(&view_id), None).await?;
      current_resources.push(view_field);

    }

    // The next_view_field_id of the created resources are expected to change,
    // so we need to get the resources again to ensure we have the correct next_view_field_ids.
    for index in 0..current_resources.len() {

      current_resources[index] = ViewField::get_by_id(&current_resources[index].id, &test_environment.database_pool).await?;

    }

  }

  // Get the "view_fields.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_view_fields_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "view_fields.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_view_field = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_view_fields_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::ResourceType::ViewField,
      scoped_view_field_id: Some(scoped_view_field.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_view_field.clone());

  }

  // Make sure the user only sees the allowed actions.
  let retrieved_resources = ViewField::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_view_fields_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
