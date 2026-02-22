use chrono::DateTime;
use uuid::Uuid;
use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Milestone, InitialMilestoneProperties};

fn assert_milestones_are_equal(milestone_1: &Milestone, milestone_2: &Milestone) {

  assert_eq!(milestone_1.id, milestone_2.id);
  assert_eq!(milestone_1.name, milestone_2.name);
  assert_eq!(milestone_1.display_name, milestone_2.display_name);
  assert_eq!(milestone_1.description, milestone_2.description);
  assert_eq!(milestone_1.start_date.and_then(|start_date| DateTime::from_timestamp_millis(start_date.timestamp_millis())), milestone_2.start_date.and_then(|start_date| DateTime::from_timestamp_millis(start_date.timestamp_millis())));
  assert_eq!(milestone_1.end_date.and_then(|end_date| DateTime::from_timestamp_millis(end_date.timestamp_millis())), milestone_2.end_date.and_then(|end_date| DateTime::from_timestamp_millis(end_date.timestamp_millis())));
  assert_eq!(milestone_1.parent_resource_type, milestone_2.parent_resource_type);
  assert_eq!(milestone_1.parent_workspace_id, milestone_2.parent_workspace_id);
  assert_eq!(milestone_1.parent_project_id, milestone_2.parent_project_id);

}

fn assert_milestone_is_equal_to_initial_properties(milestone: &Milestone, initial_properties: &InitialMilestoneProperties) {

  assert_eq!(milestone.name, initial_properties.name);
  assert_eq!(milestone.display_name, initial_properties.display_name);
  assert_eq!(milestone.description, initial_properties.description);
  assert_eq!(milestone.start_date.and_then(|start_date| DateTime::from_timestamp_millis(start_date.timestamp_millis())), initial_properties.start_date.and_then(|start_date| DateTime::from_timestamp_millis(start_date.timestamp_millis())));
  assert_eq!(milestone.end_date.and_then(|end_date| DateTime::from_timestamp_millis(end_date.timestamp_millis())), initial_properties.end_date.and_then(|end_date| DateTime::from_timestamp_millis(end_date.timestamp_millis())));
  assert_eq!(milestone.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(milestone.parent_workspace_id, initial_properties.parent_workspace_id);
  assert_eq!(milestone.parent_project_id, initial_properties.parent_project_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Milestone> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_milestone().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Milestone::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let project = test_environment.create_random_project().await?;
  let milestone_properties = InitialMilestoneProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    parent_resource_type: crate::resources::milestone::MilestoneParentResourceType::Project,
    parent_project_id: Some(project.id),
    ..Default::default()
  };
  let milestone = Milestone::create(&milestone_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_milestone_is_equal_to_initial_properties(&milestone, &milestone_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_milestone = test_environment.create_random_milestone().await?;
  
  created_milestone.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Milestone::get_by_id(&created_milestone.id, &test_environment.database_pool).await {

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

  let created_milestone = test_environment.create_random_milestone().await?;
  let retrieved_resource = Milestone::get_by_id(&created_milestone.id, &test_environment.database_pool).await?;
  assert_milestones_are_equal(&created_milestone, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut milestones: Vec<Milestone> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let milestone = test_environment.create_random_milestone().await?;
    milestones.push(milestone);

  }

  let retrieved_resources = Milestone::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Milestone> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_milestone().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Milestone::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&Milestone> = created_resources.iter().filter(|milestone| milestone.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_milestones_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Milestone> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let milestone = test_environment.create_random_milestone().await?;
    created_resources.push(milestone);

  }

  let retrieved_resources = Milestone::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_milestone = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_milestones_are_equal(created_milestone, retrieved_resource);

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
  let mut current_resources = Milestone::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let milestone = test_environment.create_random_milestone().await?;
      current_resources.push(milestone);

    }

  }

  // Get the "slashstep.milestones.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_milestones_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.milestones.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_milestone = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_milestones_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Milestone,
      scoped_milestone_id: Some(scoped_milestone.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_milestone.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = Milestone::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_milestones_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
