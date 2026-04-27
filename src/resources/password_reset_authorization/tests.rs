use chrono::{DateTime, Duration, Utc};

use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    ResourceError, ResourceType, access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, password_reset_authorization::{PasswordResetAuthorization, DEFAULT_PASSWORD_RESET_AUTHORIZATION_LIST_LIMIT, InitialPasswordResetAuthorizationProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_password_reset_authorizations_are_equal(password_reset_authorization_1: &PasswordResetAuthorization, password_reset_authorization_2: &PasswordResetAuthorization) {

  assert_eq!(password_reset_authorization_1.id, password_reset_authorization_2.id);
  assert_eq!(password_reset_authorization_1.user_id, password_reset_authorization_2.user_id);
  assert_eq!(password_reset_authorization_1.expiration_date.timestamp_millis(), password_reset_authorization_2.expiration_date.timestamp_millis());
  

}

fn assert_app_authorization_is_equal_to_initial_properties(password_reset_authorization: &PasswordResetAuthorization, initial_properties: &InitialPasswordResetAuthorizationProperties) {

  assert_eq!(password_reset_authorization.user_id, initial_properties.user_id);
  assert_eq!(password_reset_authorization.expiration_date, DateTime::from_timestamp_millis(initial_properties.expiration_date.timestamp_millis()).expect("Failed to parse expiration date."));

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_PASSWORD_RESET_AUTHORIZATION_COUNT: i64 = DEFAULT_PASSWORD_RESET_AUTHORIZATION_LIST_LIMIT + 1;
  let mut created_password_reset_authorizations: Vec<PasswordResetAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_PASSWORD_RESET_AUTHORIZATION_COUNT {

    let password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
    created_password_reset_authorizations.push(password_reset_authorization);

  }

  let retrieved_password_reset_authorization_count = PasswordResetAuthorization::count("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_password_reset_authorization_count, MAXIMUM_PASSWORD_RESET_AUTHORIZATION_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;

  // Create the access policy.
  let user = test_environment.create_random_user().await?;
  let password_reset_authorization_properties = InitialPasswordResetAuthorizationProperties {
    user_id: user.id,
    expiration_date: Utc::now() + Duration::days(30)
  };
  let password_reset_authorization = PasswordResetAuthorization::create(&password_reset_authorization_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_app_authorization_is_equal_to_initial_properties(&password_reset_authorization, &password_reset_authorization_properties);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  let created_app_authorization = test_environment.create_random_user().await?;
  
  created_app_authorization.delete(&test_environment.database_pool).await?;

  // Ensure that the access policy is no longer in the database.
  if let Err(error) = PasswordResetAuthorization::get_by_id(&created_app_authorization.id, &test_environment.database_pool).await {

    // TODO: Use assert_matches! once it is stable: https://doc.rust-lang.org/stable/core/macro.assert_matches.html
    assert!(matches!(error, ResourceError::NotFoundError(_)));

  } else {

    panic!("Expected a not found error.");

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

  let created_password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
  let retrieved_password_reset_authorization = PasswordResetAuthorization::get_by_id(&created_password_reset_authorization.id, &test_environment.database_pool).await?;
  assert_password_reset_authorizations_are_equal(&created_password_reset_authorization, &retrieved_password_reset_authorization);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_APP_AUTHORIZATION_COUNT: i64 = DEFAULT_PASSWORD_RESET_AUTHORIZATION_LIST_LIMIT + 1;
  let mut password_reset_authorizations: Vec<PasswordResetAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_APP_AUTHORIZATION_COUNT {

    let password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
    password_reset_authorizations.push(password_reset_authorization);

  }

  let retrieved_password_reset_authorizations = PasswordResetAuthorization::list("", &test_environment.database_pool, None, None).await?;

  assert_eq!(retrieved_password_reset_authorizations.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_password_reset_authorizations: Vec<PasswordResetAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
    created_password_reset_authorizations.push(password_reset_authorization);

  }
  
  let app_authorization_with_same_user_id = test_environment.create_random_password_reset_authorization(Some(&created_password_reset_authorizations[0].user_id)).await?;
  created_password_reset_authorizations.push(app_authorization_with_same_user_id);

  let query = format!("user_id = \"{}\"", created_password_reset_authorizations[0].user_id);
  let retrieved_password_reset_authorizations = PasswordResetAuthorization::list(&query, &test_environment.database_pool, None, None).await?;

  let created_password_reset_authorizations_with_specific_user_id: Vec<&PasswordResetAuthorization> = created_password_reset_authorizations.iter().filter(|password_reset_authorization| password_reset_authorization.user_id == created_password_reset_authorizations[0].user_id).collect();
  assert_eq!(created_password_reset_authorizations_with_specific_user_id.len(), retrieved_password_reset_authorizations.len());
  for i in 0..created_password_reset_authorizations_with_specific_user_id.len() {

    let created_password_reset_authorization = &created_password_reset_authorizations_with_specific_user_id[i];
    let retrieved_password_reset_authorization = &retrieved_password_reset_authorizations[i];

    assert_password_reset_authorizations_are_equal(created_password_reset_authorization, retrieved_password_reset_authorization);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_password_reset_authorizations: Vec<PasswordResetAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
    created_password_reset_authorizations.push(password_reset_authorization);

  }

  let retrieved_password_reset_authorizations = PasswordResetAuthorization::list("", &test_environment.database_pool, None, None).await?;
  assert_eq!(created_password_reset_authorizations.len(), retrieved_password_reset_authorizations.len());
  for i in 0..created_password_reset_authorizations.len() {

    let created_app_authorization = &created_password_reset_authorizations[i];
    let retrieved_app_authorization = &retrieved_password_reset_authorizations[i];

    assert_password_reset_authorizations_are_equal(created_app_authorization, retrieved_app_authorization);

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
  let mut current_password_reset_authorizations = PasswordResetAuthorization::list("", &test_environment.database_pool, None, None).await?;
  if current_password_reset_authorizations.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_password_reset_authorizations.len() as i32;
    for _ in 0..remaining_action_count {

      let password_reset_authorization = test_environment.create_random_password_reset_authorization(None).await?;
      current_password_reset_authorizations.push(password_reset_authorization);

    }

  }

  // Get the "appAuthorizations.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_password_reset_authorizations_action = Action::get_by_name("passwordResetAuthorizations.get", &test_environment.database_pool).await?;

  // Grant access to the "appAuthorizations.get" action to the user for half of the actions.
  let allowed_action_count = current_password_reset_authorizations.len() / 2;
  let mut allowed_password_reset_authorizations = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_password_reset_authorization = &current_password_reset_authorizations[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_password_reset_authorizations_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: ResourceType::PasswordResetAuthorization,
      scoped_password_reset_authorization_id: Some(scoped_password_reset_authorization.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_password_reset_authorizations.push(scoped_password_reset_authorization.clone());

  }

  // Make sure the user only sees the allowed actions.
  let retrieved_password_reset_authorizations = PasswordResetAuthorization::list("", &test_environment.database_pool, Some(&AccessPolicyPrincipalType::User), Some(&user.id)).await?;

  assert_eq!(allowed_password_reset_authorizations.len(), retrieved_password_reset_authorizations.len());
  for allowed_app_authorization in allowed_password_reset_authorizations {

    let retrieved_app_authorization = &retrieved_password_reset_authorizations.iter().find(|action| action.id == allowed_app_authorization.id).unwrap();

    assert_password_reset_authorizations_are_equal(&allowed_app_authorization, retrieved_app_authorization);

  }

  return Ok(());

}
