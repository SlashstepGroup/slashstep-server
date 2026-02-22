use uuid::Uuid;
use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Role, InitialRoleProperties};

fn assert_roles_are_equal(role_1: &Role, role_2: &Role) {

  assert_eq!(role_1.id, role_2.id);
  assert_eq!(role_1.name, role_2.name);
  assert_eq!(role_1.display_name, role_2.display_name);
  assert_eq!(role_1.description, role_2.description);
  assert_eq!(role_1.parent_resource_type, role_2.parent_resource_type);
  assert_eq!(role_1.parent_workspace_id, role_2.parent_workspace_id);
  assert_eq!(role_1.parent_project_id, role_2.parent_project_id);
  assert_eq!(role_1.parent_group_id, role_2.parent_group_id);

}

fn assert_role_is_equal_to_initial_properties(role: &Role, initial_properties: &InitialRoleProperties) {

  assert_eq!(role.name, initial_properties.name);
  assert_eq!(role.display_name, initial_properties.display_name);
  assert_eq!(role.description, initial_properties.description);
  assert_eq!(role.parent_resource_type, initial_properties.parent_resource_type);
  assert_eq!(role.parent_workspace_id, initial_properties.parent_workspace_id);
  assert_eq!(role.parent_project_id, initial_properties.parent_project_id);
  assert_eq!(role.parent_group_id, initial_properties.parent_group_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<Role> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_role().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = Role::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let project = test_environment.create_random_project().await?;
  let role_properties = InitialRoleProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Some(Uuid::now_v7().to_string()),
    parent_resource_type: crate::resources::role::RoleParentResourceType::Project,
    parent_project_id: Some(project.id),
    ..Default::default()
  };
  let role = Role::create(&role_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_role_is_equal_to_initial_properties(&role, &role_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_role = test_environment.create_random_role().await?;
  
  created_role.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match Role::get_by_id(&created_role.id, &test_environment.database_pool).await {

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

  let created_role = test_environment.create_random_role().await?;
  let retrieved_resource = Role::get_by_id(&created_role.id, &test_environment.database_pool).await?;
  assert_roles_are_equal(&created_role, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut roles: Vec<Role> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let role = test_environment.create_random_role().await?;
    roles.push(role);

  }

  let retrieved_resources = Role::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<Role> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_role().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = Role::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&Role> = created_resources.iter().filter(|role| role.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_roles_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<Role> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let role = test_environment.create_random_role().await?;
    created_resources.push(role);

  }

  let retrieved_resources = Role::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_role = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_roles_are_equal(created_role, retrieved_resource);

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
  let mut current_resources = Role::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let role = test_environment.create_random_role().await?;
      current_resources.push(role);

    }

  }

  // Get the "slashstep.roles.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_roles_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.roles.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_role = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_roles_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Role,
      scoped_role_id: Some(scoped_role.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_role.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = Role::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_roles_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
