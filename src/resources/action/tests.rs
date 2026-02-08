use uuid::Uuid;
use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource,
    access_policy::{ 
      AccessPolicy, 
      ActionPermissionLevel, 
      AccessPolicyPrincipalType, 
      AccessPolicyResourceType, 
      IndividualPrincipal, 
      InitialAccessPolicyProperties
    }, 
    action::{
      Action, ActionParentResourceType, DEFAULT_ACTION_LIST_LIMIT, EditableActionProperties, InitialActionProperties
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_actions_are_equal(action_1: &Action, action_2: &Action) {

  assert_eq!(action_1.id, action_2.id);
  assert_eq!(action_1.name, action_2.name);
  assert_eq!(action_1.display_name, action_2.display_name);
  assert_eq!(action_1.description, action_2.description);
  assert_eq!(action_1.parent_app_id, action_2.parent_app_id);

}

fn assert_action_is_equal_to_initial_properties(action: &Action, initial_properties: &InitialActionProperties) {

  assert_eq!(action.name, initial_properties.name);
  assert_eq!(action.display_name, initial_properties.display_name);
  assert_eq!(action.description, initial_properties.description);
  assert_eq!(action.parent_app_id, initial_properties.parent_app_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACTION_LIST_LIMIT + 1;
  let mut created_actions: Vec<Action> = Vec::new();
  for _ in 0..MAXIMUM_ACTION_COUNT {

    let action = test_environment.create_random_action(None).await?;
    created_actions.push(action);

  }

  let retrieved_action_count = Action::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_action_count, MAXIMUM_ACTION_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let action_properties = InitialActionProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string(),
    ..Default::default()
  };
  let action = Action::create(&action_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_action_is_equal_to_initial_properties(&action, &action_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_action = test_environment.create_random_action(None).await?;

  created_action.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  let retrieved_action_result = Action::get_by_id(&created_action.id, &test_environment.database_pool).await;
  assert!(retrieved_action_result.is_err());

  return Ok(());

}

#[tokio::test]
async fn initialize_resource_table() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  return Ok(());

}

#[tokio::test]
async fn verify_get_action_by_id() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let action = test_environment.create_random_action(None).await?;
  let retrieved_action = Action::get_by_id(&action.id, &test_environment.database_pool).await?;
  assert_actions_are_equal(&action, &retrieved_action);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of access policies by default.
#[tokio::test]
async fn list_actions_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACTION_LIST_LIMIT + 1;
  let mut created_actions: Vec<Action> = Vec::new();
  for _ in 0..MAXIMUM_ACTION_COUNT {

    let action = test_environment.create_random_action(None).await?;
    created_actions.push(action);

  }

  let retrieved_actions = Action::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_actions.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of access policies can be retrieved with a query.
#[tokio::test]
async fn list_actions_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_ACTION_COUNT: i32 = 5;
  let mut created_actions: Vec<Action> = Vec::new();
  for _ in 0..MAXIMUM_ACTION_COUNT {

    let action = test_environment.create_random_action(None).await?;
    created_actions.push(action);

  }
  
  let action_with_same_display_name = Action::create(&InitialActionProperties {
    name: Uuid::now_v7().to_string(),
    display_name: created_actions[0].display_name.clone(),
    description: Uuid::now_v7().to_string(),
    parent_app_id: None,
    parent_resource_type: ActionParentResourceType::Server
  }, &test_environment.database_pool).await?;
  created_actions.push(action_with_same_display_name);

  let query = format!("display_name = \"{}\"", created_actions[0].display_name);
  let retrieved_actions = Action::list(&query, &test_environment.database_pool, None).await?;

  let created_actions_with_specific_display_name: Vec<&Action> = created_actions.iter().filter(|action| action.display_name == created_actions[0].display_name).collect();
  assert_eq!(created_actions_with_specific_display_name.len(), retrieved_actions.len());
  for i in 0..created_actions_with_specific_display_name.len() {

    let created_action = &created_actions_with_specific_display_name[i];
    let retrieved_action = &retrieved_actions[i];

    assert_actions_are_equal(created_action, retrieved_action);

  }

  return Ok(());

}

#[tokio::test]
async fn list_actions_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_ACTION_COUNT: i32 = 25;
  let mut created_actions: Vec<Action> = Vec::new();
  for _ in 0..MAXIMUM_ACTION_COUNT {

    let action = test_environment.create_random_action(None).await?;
    created_actions.push(action);

  }

  let retrieved_actions = Action::list("", &test_environment.database_pool, None).await?;

  assert_eq!(created_actions.len(), retrieved_actions.len());
  for i in 0..created_actions.len() {

    let created_action = &created_actions[i];
    let retrieved_action = &retrieved_actions[i];

    assert_actions_are_equal(created_action, retrieved_action);

  }

  return Ok(());

}

/// Verifies that a list of access policies can be retrieved without a query.
#[tokio::test]
async fn list_access_policies_without_query_and_filter_based_on_requestor_permissions() -> Result<(), TestSlashstepServerError> {

  // Make sure there are at least two actions.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MINIMUM_ACTION_COUNT: i32 = 2;
  let mut current_actions = Action::list("", &test_environment.database_pool, None).await?;
  if current_actions.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_actions.len() as i32;
    for _ in 0..remaining_action_count {

      let action = test_environment.create_random_action(None).await?;
      current_actions.push(action);

    }

  }

  // Get the "slashstep.actions.get" action one time.
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let user = test_environment.create_random_user().await?;
  let get_actions_action = Action::get_by_name("slashstep.actions.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.actions.get" action to the user for half of the actions.
  let allowed_action_count = current_actions.len() / 2;
  let mut allowed_actions = Vec::new();
  for index in 0..allowed_action_count {

    let action = &current_actions[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_actions_action.id.clone(),
      permission_level: ActionPermissionLevel::User,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: AccessPolicyResourceType::Action,
      scoped_action_id: Some(action.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_actions.push(action.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = IndividualPrincipal::User(user.id);
  let retrieved_actions = Action::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_actions.len(), retrieved_actions.len());
  for allowed_action in allowed_actions {

    let retrieved_action = &retrieved_actions.iter().find(|action| action.id == allowed_action.id).unwrap();

    assert_actions_are_equal(&allowed_action, retrieved_action);

  }

  return Ok(());

}

#[tokio::test]
async fn update_action() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;

  // Create the action and update it.
  initialize_required_tables(&test_environment.database_pool).await?;
  let original_action = test_environment.create_random_action(None).await?;
  let new_name = Uuid::now_v7().to_string();
  let new_display_name = Uuid::now_v7().to_string();
  let new_description = Uuid::now_v7().to_string();
  let updated_action = original_action.update(&EditableActionProperties {
    name: Some(new_name.clone()),
    display_name: Some(new_display_name.clone()),
    description: Some(new_description.clone())
  }, &test_environment.database_pool).await?;

  // Verify the new action.
  assert_eq!(original_action.id, updated_action.id);
  assert_eq!(new_name, updated_action.name);
  assert_eq!(new_display_name, updated_action.display_name);
  assert_eq!(new_description, updated_action.description);
  assert_eq!(original_action.parent_app_id, updated_action.parent_app_id);
  assert_eq!(original_action.parent_resource_type, updated_action.parent_resource_type);

  return Ok(());

}