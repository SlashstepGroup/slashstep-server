use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Project, InitialProjectProperties};

fn assert_projects_are_equal(project_1: &Project, project_2: &Project) {

  assert_eq!(project_1.id, project_2.id);
  assert_eq!(project_1.name, project_2.name);
  assert_eq!(project_1.display_name, project_2.display_name);
  assert_eq!(project_1.key, project_2.key);
  assert_eq!(project_1.description, project_2.description);
  assert_eq!(project_1.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), project_2.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(project_1.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), project_2.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(project_1.workspace_id, project_2.workspace_id);

}

fn assert_project_is_equal_to_initial_properties(project: &Project, initial_properties: &InitialProjectProperties) {

  assert_eq!(project.name, initial_properties.name);
  assert_eq!(project.display_name, initial_properties.display_name);
  assert_eq!(project.key, initial_properties.key);
  assert_eq!(project.description, initial_properties.description);
  assert_eq!(project.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), initial_properties.start_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(project.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), initial_properties.end_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(project.workspace_id, initial_properties.workspace_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Project> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_project().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Project::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let workspace = test_environment.create_random_workspace().await?;
  let field_properties = InitialProjectProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    key: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    start_date: Some(Utc::now()),
    end_date: Some(Utc::now()),
    workspace_id: workspace.id,
    ..Default::default()
  };
  let project = Project::create(&field_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_project_is_equal_to_initial_properties(&project, &field_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_project = test_environment.create_random_project().await?;
  
  created_project.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Project::get_by_id(&created_project.id, &test_environment.database_pool).await {

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

  let created_project = test_environment.create_random_project().await?;
  let retrieved_resource = Project::get_by_id(&created_project.id, &test_environment.database_pool).await?;
  assert_projects_are_equal(&created_project, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut fields: Vec<Project> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let project = test_environment.create_random_project().await?;
    fields.push(project);

  }

  let retrieved_resources = Project::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Project> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_project().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Project::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&Project> = created_resources.iter().filter(|project| project.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_projects_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Project> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let project = test_environment.create_random_project().await?;
    created_resources.push(project);

  }

  let retrieved_resources = Project::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_project = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_projects_are_equal(created_project, retrieved_resource);

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
  let mut current_resources = Project::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let project = test_environment.create_random_project().await?;
      current_resources.push(project);

    }

  }

  // Get the "slashstep.fields.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_fields_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.fields.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_project = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_fields_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Project,
      scoped_project_id: Some(scoped_project.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_project.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = Project::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_projects_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
