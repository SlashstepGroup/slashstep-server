use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, ed25519::signature::rand_core::OsRng, pkcs8::{EncodePublicKey, spki::der::pem::LineEnding}};
use local_ip_address::local_ip;
use uuid::Uuid;

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, app_credential::{AppCredential, DEFAULT_APP_CREDENTIAL_LIST_LIMIT, InitialAppCredentialProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_app_credentials_are_equal(app_credential_1: &AppCredential, app_credential_2: &AppCredential) {

  assert_eq!(app_credential_1.id, app_credential_2.id);
  assert_eq!(app_credential_1.app_id, app_credential_2.app_id);
  assert_eq!(app_credential_1.description, app_credential_2.description);
  assert_eq!(app_credential_1.expiration_date, app_credential_2.expiration_date);
  assert_eq!(app_credential_1.creation_ip_address, app_credential_2.creation_ip_address);
  assert_eq!(app_credential_1.public_key, app_credential_2.public_key);

}

fn assert_app_credential_is_equal_to_initial_properties(app_credential: &AppCredential, initial_properties: &InitialAppCredentialProperties) {

  assert_eq!(app_credential.app_id, initial_properties.app_id);
  assert_eq!(app_credential.description, initial_properties.description);
  assert_eq!(app_credential.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())), initial_properties.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())));
  assert_eq!(app_credential.creation_ip_address, initial_properties.creation_ip_address);
  assert_eq!(app_credential.public_key, initial_properties.public_key);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_CREDENTIAL_COUNT: i64 = DEFAULT_APP_CREDENTIAL_LIST_LIMIT + 1;
  let mut created_app_credentials: Vec<AppCredential> = Vec::new();
  for _ in 0..MAXIMUM_APP_CREDENTIAL_COUNT {

    let app_credential = test_environment.create_random_app_credential(None).await?;
    created_app_credentials.push(app_credential);

  }

  let retrieved_app_credential_count = AppCredential::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_credential_count, MAXIMUM_APP_CREDENTIAL_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the resource.
  let mut os_rng = OsRng;
  let signing_key = SigningKey::generate(&mut os_rng);
  let public_key = signing_key.verifying_key().to_public_key_pem(LineEnding::LF)?;
  let app = test_environment.create_random_app().await?;
  let app_credential_properties = InitialAppCredentialProperties {
    app_id: app.id,
    description: Some(Uuid::now_v7().to_string()),
    expiration_date: Some(Utc::now() + Duration::days(30)),
    creation_ip_address: local_ip()?,
    public_key: public_key.clone()
  };
  let app_credential = AppCredential::create(&app_credential_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_app_credential_is_equal_to_initial_properties(&app_credential, &app_credential_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_app_credential = test_environment.create_random_app_credential(None).await?;
  
  created_app_credential.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match AppCredential::get_by_id(&created_app_credential.id, &test_environment.database_pool).await {

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

  let created_app_credential = test_environment.create_random_app_credential(None).await?;
  let retrieved_app_credential = AppCredential::get_by_id(&created_app_credential.id, &test_environment.database_pool).await?;
  assert_app_credentials_are_equal(&created_app_credential, &retrieved_app_credential);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_CREDENTIAL_COUNT: i64 = DEFAULT_APP_CREDENTIAL_LIST_LIMIT + 1;
  let mut app_credentials: Vec<AppCredential> = Vec::new();
  for _ in 0..MAXIMUM_APP_CREDENTIAL_COUNT {

    let app_credential = test_environment.create_random_app_credential(None).await?;
    app_credentials.push(app_credential);

  }

  let retrieved_app_credentials = AppCredential::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_credentials.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_app_credentials: Vec<AppCredential> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_credential = test_environment.create_random_app_credential(None).await?;
    created_app_credentials.push(app_credential);

  }
  
  let app_credential_with_same_app_id = test_environment.create_random_app_credential(Some(&created_app_credentials[0].app_id)).await?;
  created_app_credentials.push(app_credential_with_same_app_id);

  let query = format!("app_id = \"{}\"", created_app_credentials[0].app_id);
  let retrieved_app_credentials = AppCredential::list(&query, &test_environment.database_pool, None).await?;

  let created_app_credentials_with_specific_app_id: Vec<&AppCredential> = created_app_credentials.iter().filter(|app_credential| app_credential.app_id == created_app_credentials[0].app_id).collect();
  assert_eq!(created_app_credentials_with_specific_app_id.len(), retrieved_app_credentials.len());
  for i in 0..created_app_credentials_with_specific_app_id.len() {

    let created_app_credential = &created_app_credentials_with_specific_app_id[i];
    let retrieved_app_credential = &retrieved_app_credentials[i];

    assert_app_credentials_are_equal(created_app_credential, retrieved_app_credential);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_app_credentials: Vec<AppCredential> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_credential = test_environment.create_random_app_credential(None).await?;
    created_app_credentials.push(app_credential);

  }

  let retrieved_app_credentials = AppCredential::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_app_credentials.len(), retrieved_app_credentials.len());
  for i in 0..created_app_credentials.len() {

    let created_app_credential = &created_app_credentials[i];
    let retrieved_app_credential = &retrieved_app_credentials[i];

    assert_app_credentials_are_equal(created_app_credential, retrieved_app_credential);

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
  let mut current_app_credentials = AppCredential::list("", &test_environment.database_pool, None).await?;
  if current_app_credentials.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_app_credentials.len() as i32;
    for _ in 0..remaining_action_count {

      let app_credential = test_environment.create_random_app_credential(None).await?;
      current_app_credentials.push(app_credential);

    }

  }

  // Get the "slashstep.appCredentials.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_app_credentials_action = Action::get_by_name("slashstep.appCredentials.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.appCredentials.get" action to the user for half of the actions.
  let allowed_action_count = current_app_credentials.len() / 2;
  let mut allowed_app_credentials = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_app_credential = &current_app_credentials[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_app_credentials_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::AppCredential,
      scoped_app_credential_id: Some(scoped_app_credential.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_app_credentials.push(scoped_app_credential.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_app_credentials = AppCredential::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_app_credentials.len(), retrieved_app_credentials.len());
  for allowed_app_credential in allowed_app_credentials {

    let retrieved_app_credential = &retrieved_app_credentials.iter().find(|action| action.id == allowed_app_credential.id).unwrap();

    assert_app_credentials_are_equal(&allowed_app_credential, retrieved_app_credential);

  }

  return Ok(());

}
