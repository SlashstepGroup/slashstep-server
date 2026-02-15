use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, server_log_entry::ServerLogEntryLevel
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, ServerLogEntry, InitialServerLogEntryProperties};

fn assert_server_log_entries_are_equal(server_log_entry_1: &ServerLogEntry, server_log_entry_2: &ServerLogEntry) {

  assert_eq!(server_log_entry_1.id, server_log_entry_2.id);
  assert_eq!(server_log_entry_1.message, server_log_entry_2.message);
  assert_eq!(server_log_entry_1.http_transaction_id, server_log_entry_2.http_transaction_id);
  assert_eq!(server_log_entry_1.level, server_log_entry_2.level);

}

fn assert_server_log_entry_is_equal_to_initial_properties(server_log_entry: &ServerLogEntry, initial_properties: &InitialServerLogEntryProperties) {

  assert_eq!(server_log_entry.message, initial_properties.message);
  assert_eq!(server_log_entry.http_transaction_id, initial_properties.http_transaction_id);
  assert_eq!(server_log_entry.level, initial_properties.level);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<ServerLogEntry> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_server_log_entry().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = ServerLogEntry::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let server_log_entry_properties = InitialServerLogEntryProperties {
    message: Uuid::now_v7().to_string(),
    http_transaction_id: None,
    level: ServerLogEntryLevel::Info
  };
  let server_log_entry = ServerLogEntry::create(&server_log_entry_properties, &test_environment.database_pool).await?;
  assert_server_log_entry_is_equal_to_initial_properties(&server_log_entry, &server_log_entry_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_server_log_entry = test_environment.create_random_server_log_entry().await?;
  
  created_server_log_entry.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match ServerLogEntry::get_by_id(&created_server_log_entry.id, &test_environment.database_pool).await {

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

  let created_server_log_entry = test_environment.create_random_server_log_entry().await?;
  let retrieved_resource = ServerLogEntry::get_by_id(&created_server_log_entry.id, &test_environment.database_pool).await?;
  assert_server_log_entries_are_equal(&created_server_log_entry, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut server_log_entries: Vec<ServerLogEntry> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let server_log_entry = test_environment.create_random_server_log_entry().await?;
    server_log_entries.push(server_log_entry);

  }

  let retrieved_resources = ServerLogEntry::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<ServerLogEntry> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_server_log_entry().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = ServerLogEntry::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&ServerLogEntry> = created_resources.iter().filter(|server_log_entry| server_log_entry.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_server_log_entries_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<ServerLogEntry> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let server_log_entry = test_environment.create_random_server_log_entry().await?;
    created_resources.push(server_log_entry);

  }

  let retrieved_resources = ServerLogEntry::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_server_log_entry = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_server_log_entries_are_equal(created_server_log_entry, retrieved_resource);

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
  let mut current_resources = ServerLogEntry::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let server_log_entry = test_environment.create_random_server_log_entry().await?;
      current_resources.push(server_log_entry);

    }

  }

  // Get the "slashstep.server_log_entries.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_server_log_entries_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.server_log_entries.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_server_log_entry = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_server_log_entries_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::ServerLogEntry,
      scoped_server_log_entry_id: Some(scoped_server_log_entry.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_server_log_entry);

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = ServerLogEntry::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_server_log_entries_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
