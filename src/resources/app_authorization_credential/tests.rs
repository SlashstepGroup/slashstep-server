use chrono::{DateTime, Duration, Utc};

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, initialize_predefined_configurations, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, app_authorization_credential::{AppAuthorizationCredential, DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT, InitialAppAuthorizationCredentialProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_app_authorization_credentials_are_equal(app_authorization_credential_1: &AppAuthorizationCredential, app_authorization_credential_2: &AppAuthorizationCredential) {

  assert_eq!(app_authorization_credential_1.id, app_authorization_credential_2.id);
  assert_eq!(app_authorization_credential_1.app_authorization_id, app_authorization_credential_2.app_authorization_id);
  assert_eq!(app_authorization_credential_1.access_token_expiration_date, app_authorization_credential_2.access_token_expiration_date);
  assert_eq!(app_authorization_credential_1.refresh_token_expiration_date, app_authorization_credential_2.refresh_token_expiration_date);
  assert_eq!(app_authorization_credential_1.refreshed_app_authorization_credential_id, app_authorization_credential_2.refreshed_app_authorization_credential_id);
  

}

fn assert_app_authorization_is_equal_to_initial_properties(app_authorization_credential: &AppAuthorizationCredential, initial_properties: &InitialAppAuthorizationCredentialProperties) {

  assert_eq!(app_authorization_credential.app_authorization_id, initial_properties.app_authorization_id);
  assert_eq!(app_authorization_credential.access_token_expiration_date, DateTime::from_timestamp_millis(initial_properties.access_token_expiration_date.timestamp_millis()).expect("Failed to parse access token expiration date."));
  assert_eq!(app_authorization_credential.refresh_token_expiration_date, DateTime::from_timestamp_millis(initial_properties.refresh_token_expiration_date.timestamp_millis()).expect("Failed to parse refresh token expiration date."));
  assert_eq!(app_authorization_credential.refreshed_app_authorization_credential_id, initial_properties.refreshed_app_authorization_credential_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_AUTHORIZATION_CREDENTIAL_COUNT: i64 = DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT + 1;
  let mut created_app_authorization_credentials: Vec<AppAuthorizationCredential> = Vec::new();
  for _ in 0..MAXIMUM_APP_AUTHORIZATION_CREDENTIAL_COUNT {

    let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
    created_app_authorization_credentials.push(app_authorization_credential);

  }

  let retrieved_app_authorization_credential_count = AppAuthorizationCredential::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_authorization_credential_count, MAXIMUM_APP_AUTHORIZATION_CREDENTIAL_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let app_authorization = test_environment.create_random_app_authorization(None).await?;
  let app_authorization_credential_properties = InitialAppAuthorizationCredentialProperties {
    app_authorization_id: app_authorization.id,
    access_token_expiration_date: Utc::now() + Duration::days(30),
    refresh_token_expiration_date: Utc::now() + Duration::days(30),
    ..Default::default()
  };
  let app_authorization_credential = AppAuthorizationCredential::create(&app_authorization_credential_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_app_authorization_is_equal_to_initial_properties(&app_authorization_credential, &app_authorization_credential_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  let created_app_authorization = test_environment.create_random_app_authorization(None).await?;
  
  created_app_authorization.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  match AppAuthorizationCredential::get_by_id(&created_app_authorization.id, &test_environment.database_pool).await {

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

  let created_app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
  let retrieved_app_authorization_credential = AppAuthorizationCredential::get_by_id(&created_app_authorization_credential.id, &test_environment.database_pool).await?;
  assert_app_authorization_credentials_are_equal(&created_app_authorization_credential, &retrieved_app_authorization_credential);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_AUTHORIZATION_COUNT: i64 = DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT + 1;
  let mut app_authorization_credentials: Vec<AppAuthorizationCredential> = Vec::new();
  for _ in 0..MAXIMUM_APP_AUTHORIZATION_COUNT {

    let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
    app_authorization_credentials.push(app_authorization_credential);

  }

  let retrieved_app_authorization_credentials = AppAuthorizationCredential::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_authorization_credentials.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_app_authorization_credentials: Vec<AppAuthorizationCredential> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
    created_app_authorization_credentials.push(app_authorization_credential);

  }
  
  let app_authorization_with_same_app_authorization_id = test_environment.create_random_app_authorization_credential(Some(&created_app_authorization_credentials[0].app_authorization_id)).await?;
  created_app_authorization_credentials.push(app_authorization_with_same_app_authorization_id);

  let query = format!("app_authorization_id = \"{}\"", created_app_authorization_credentials[0].app_authorization_id);
  let retrieved_app_authorization_credentials = AppAuthorizationCredential::list(&query, &test_environment.database_pool, None).await?;

  let created_app_authorization_credentials_with_specific_app_id: Vec<&AppAuthorizationCredential> = created_app_authorization_credentials.iter().filter(|app_authorization_credential| app_authorization_credential.app_authorization_id == created_app_authorization_credentials[0].app_authorization_id).collect();
  assert_eq!(created_app_authorization_credentials_with_specific_app_id.len(), retrieved_app_authorization_credentials.len());
  for i in 0..created_app_authorization_credentials_with_specific_app_id.len() {

    let created_app_authorization = &created_app_authorization_credentials_with_specific_app_id[i];
    let retrieved_app_authorization = &retrieved_app_authorization_credentials[i];

    assert_app_authorization_credentials_are_equal(created_app_authorization, retrieved_app_authorization);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_app_authorization_credentials: Vec<AppAuthorizationCredential> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
    created_app_authorization_credentials.push(app_authorization_credential);

  }

  let retrieved_app_authorization_credentials = AppAuthorizationCredential::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_app_authorization_credentials.len(), retrieved_app_authorization_credentials.len());
  for i in 0..created_app_authorization_credentials.len() {

    let created_app_authorization = &created_app_authorization_credentials[i];
    let retrieved_app_authorization = &retrieved_app_authorization_credentials[i];

    assert_app_authorization_credentials_are_equal(created_app_authorization, retrieved_app_authorization);

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
  let mut current_app_authorization_credentials = AppAuthorizationCredential::list("", &test_environment.database_pool, None).await?;
  if current_app_authorization_credentials.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_app_authorization_credentials.len() as i32;
    for _ in 0..remaining_action_count {

      let app_authorization_credential = test_environment.create_random_app_authorization_credential(None).await?;
      current_app_authorization_credentials.push(app_authorization_credential);

    }

  }

  // Get the "slashstep.appAuthorizations.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_app_authorization_credentials_action = Action::get_by_name("slashstep.appAuthorizationCredentials.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.appAuthorizations.get" action to the user for half of the actions.
  let allowed_action_count = current_app_authorization_credentials.len() / 2;
  let mut allowed_app_authorization_credentials = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_app_authorization_credential = &current_app_authorization_credentials[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_app_authorization_credentials_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::AppAuthorizationCredential,
      scoped_app_authorization_credential_id: Some(scoped_app_authorization_credential.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_app_authorization_credentials.push(scoped_app_authorization_credential.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_app_authorization_credentials = AppAuthorizationCredential::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_app_authorization_credentials.len(), retrieved_app_authorization_credentials.len());
  for allowed_app_authorization in allowed_app_authorization_credentials {

    let retrieved_app_authorization = &retrieved_app_authorization_credentials.iter().find(|action| action.id == allowed_app_authorization.id).unwrap();

    assert_app_authorization_credentials_are_equal(&allowed_app_authorization, retrieved_app_authorization);

  }

  return Ok(());

}
