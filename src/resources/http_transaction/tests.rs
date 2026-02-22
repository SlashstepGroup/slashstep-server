use chrono::{DateTime, Duration, Utc};
use local_ip_address::local_ip;
use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }
  }, tests::{TestEnvironment, TestSlashstepServerError}
};
use super::{DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, HTTPTransaction, InitialHTTPTransactionProperties};

fn assert_http_transactions_are_equal(http_transaction_1: &HTTPTransaction, http_transaction_2: &HTTPTransaction) {

  assert_eq!(http_transaction_1.id, http_transaction_2.id);
  assert_eq!(http_transaction_1.method, http_transaction_2.method);
  assert_eq!(http_transaction_1.url, http_transaction_2.url);
  assert_eq!(http_transaction_1.ip_address, http_transaction_2.ip_address);
  assert_eq!(http_transaction_1.headers, http_transaction_2.headers);
  assert_eq!(http_transaction_1.status_code, http_transaction_2.status_code);
  assert_eq!(http_transaction_1.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), http_transaction_2.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));

}

fn assert_http_transaction_is_equal_to_initial_properties(http_transaction: &HTTPTransaction, initial_properties: &InitialHTTPTransactionProperties) {

  assert_eq!(http_transaction.method, initial_properties.method);
  assert_eq!(http_transaction.url, initial_properties.url);
  assert_eq!(http_transaction.ip_address, initial_properties.ip_address);
  assert_eq!(http_transaction.headers, initial_properties.headers);
  assert_eq!(http_transaction.status_code, initial_properties.status_code);
  assert_eq!(http_transaction.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), initial_properties.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut created_resources: Vec<HTTPTransaction> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_http_transaction().await?;
    created_resources.push(resource);

  }

  let retrieved_resource_count = HTTPTransaction::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  let http_transaction_properties = InitialHTTPTransactionProperties {
    method: "GET".to_string(),
    url: Uuid::now_v7().to_string(),
    ip_address: local_ip()?,
    headers: Uuid::now_v7().to_string(),
    status_code: Some(200),
    expiration_date: Some(Utc::now() + Duration::days(30))
  };
  let http_transaction = HTTPTransaction::create(&http_transaction_properties, &test_environment.database_pool).await?;
  assert_http_transaction_is_equal_to_initial_properties(&http_transaction, &http_transaction_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_http_transaction = test_environment.create_random_http_transaction().await?;
  
  created_http_transaction.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match HTTPTransaction::get_by_id(&created_http_transaction.id, &test_environment.database_pool).await {

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

  let created_http_transaction = test_environment.create_random_http_transaction().await?;
  let retrieved_resource = HTTPTransaction::get_by_id(&created_http_transaction.id, &test_environment.database_pool).await?;
  assert_http_transactions_are_equal(&created_http_transaction, &retrieved_resource);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
  let mut http_transactions: Vec<HTTPTransaction> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let http_transaction = test_environment.create_random_http_transaction().await?;
    http_transactions.push(http_transaction);

  }

  let retrieved_resources = HTTPTransaction::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_resources.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_resources: Vec<HTTPTransaction> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let resource = test_environment.create_random_http_transaction().await?;
    created_resources.push(resource);

  }

  let query = format!("id = \"{}\"", created_resources[0].id);
  let retrieved_resources = HTTPTransaction::list(&query, &test_environment.database_pool, None).await?;

  let created_resources_with_specific_id: Vec<&HTTPTransaction> = created_resources.iter().filter(|http_transaction| http_transaction.id == created_resources[0].id).collect();
  assert_eq!(created_resources_with_specific_id.len(), retrieved_resources.len());
  for i in 0..created_resources_with_specific_id.len() {

    let created_resource = &created_resources_with_specific_id[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_http_transactions_are_equal(created_resource, retrieved_resource);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_resources: Vec<HTTPTransaction> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let http_transaction = test_environment.create_random_http_transaction().await?;
    created_resources.push(http_transaction);

  }

  let retrieved_resources = HTTPTransaction::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_resources.len(), retrieved_resources.len());
  for i in 0..created_resources.len() {

    let created_http_transaction = &created_resources[i];
    let retrieved_resource = &retrieved_resources[i];

    assert_http_transactions_are_equal(created_http_transaction, retrieved_resource);

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
  let mut current_resources = HTTPTransaction::list("", &test_environment.database_pool, None).await?;
  if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {

    let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
    for _ in 0..remaining_action_count {

      let http_transaction = test_environment.create_random_http_transaction().await?;
      current_resources.push(http_transaction);

    }

  }

  // Get the "slashstep.http_transactions.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_http_transactions_action = Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

  // Grant access to the "slashstep.http_transactions.get" action to the user for half of the actions.
  let allowed_resource_count = current_resources.len() / 2;
  let mut allowed_resources = Vec::new();
  for index in 0..allowed_resource_count {

    let scoped_http_transaction = &current_resources[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_http_transactions_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::HTTPTransaction,
      scoped_http_transaction_id: Some(scoped_http_transaction.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_resources.push(scoped_http_transaction.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_resources = HTTPTransaction::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_resources.len(), retrieved_resources.len());
  for allowed_resource in allowed_resources {

    let retrieved_resource = &retrieved_resources.iter().find(|action| action.id == allowed_resource.id).expect("Expected a retrieved resource with the same ID.");

    assert_http_transactions_are_equal(&allowed_resource, retrieved_resource);

  }

  return Ok(());

}
