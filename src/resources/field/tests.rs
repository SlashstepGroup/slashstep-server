use crate::{
  initialize_required_tables, predefinitions::initialize_predefined_actions, resources::{
    DeletableResource, ResourceError, access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{
      Action, DEFAULT_ACTION_LIST_LIMIT
    }, app_authorization::{AppAuthorization, AppAuthorizationAuthorizingResourceType, DEFAULT_APP_AUTHORIZATION_LIST_LIMIT, InitialAppAuthorizationProperties}
  }, tests::{TestEnvironment, TestSlashstepServerError}
};

fn assert_app_authorizations_are_equal(app_authorization_1: &AppAuthorization, app_authorization_2: &AppAuthorization) {

  assert_eq!(app_authorization_1.id, app_authorization_2.id);
  assert_eq!(app_authorization_1.app_id, app_authorization_2.app_id);
  assert_eq!(app_authorization_1.authorizing_resource_type, app_authorization_2.authorizing_resource_type);
  assert_eq!(app_authorization_1.authorizing_project_id, app_authorization_2.authorizing_project_id);
  assert_eq!(app_authorization_1.authorizing_workspace_id, app_authorization_2.authorizing_workspace_id);
  assert_eq!(app_authorization_1.authorizing_user_id, app_authorization_2.authorizing_user_id);

}

fn assert_app_authorization_is_equal_to_initial_properties(app_authorization: &AppAuthorization, initial_properties: &InitialAppAuthorizationProperties) {

  assert_eq!(app_authorization.app_id, initial_properties.app_id);
  assert_eq!(app_authorization.authorizing_resource_type, initial_properties.authorizing_resource_type);
  assert_eq!(app_authorization.authorizing_project_id, initial_properties.authorizing_project_id);
  assert_eq!(app_authorization.authorizing_workspace_id, initial_properties.authorizing_workspace_id);
  assert_eq!(app_authorization.authorizing_user_id, initial_properties.authorizing_user_id);

}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_AUTHORIZATION_COUNT: i64 = DEFAULT_APP_AUTHORIZATION_LIST_LIMIT + 1;
  let mut created_app_authorizations: Vec<AppAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_APP_AUTHORIZATION_COUNT {

    let app_authorization = test_environment.create_random_app_authorization(None).await?;
    created_app_authorizations.push(app_authorization);

  }

  let retrieved_app_authorization_count = AppAuthorization::count("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_authorization_count, MAXIMUM_APP_AUTHORIZATION_COUNT);

  return Ok(());

}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;

  // Create the access policy.
  let app = test_environment.create_random_app().await?;
  let app_authorization_properties = InitialAppAuthorizationProperties {
    app_id: app.id,
    authorizing_resource_type: AppAuthorizationAuthorizingResourceType::Server,
    ..Default::default()
  };
  let app_authorization = AppAuthorization::create(&app_authorization_properties, &test_environment.database_pool).await?;

  // Ensure that all the properties were set correctly.
  assert_app_authorization_is_equal_to_initial_properties(&app_authorization, &app_authorization_properties);

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
  match AppAuthorization::get_by_id(&created_app_authorization.id, &test_environment.database_pool).await {

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

  let created_app_authorization = test_environment.create_random_app_authorization(None).await?;
  let retrieved_app_authorization = AppAuthorization::get_by_id(&created_app_authorization.id, &test_environment.database_pool).await?;
  assert_app_authorizations_are_equal(&created_app_authorization, &retrieved_app_authorization);

  return Ok(());

}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_APP_AUTHORIZATION_COUNT: i64 = DEFAULT_APP_AUTHORIZATION_LIST_LIMIT + 1;
  let mut app_authorizations: Vec<AppAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_APP_AUTHORIZATION_COUNT {

    let app_authorization = test_environment.create_random_app_authorization(None).await?;
    app_authorizations.push(app_authorization);

  }

  let retrieved_app_authorizations = AppAuthorization::list("", &test_environment.database_pool, None).await?;

  assert_eq!(retrieved_app_authorizations.len(), DEFAULT_ACTION_LIST_LIMIT as usize);

  return Ok(());
  
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 5;
  let mut created_app_authorizations: Vec<AppAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_authorization = test_environment.create_random_app_authorization(None).await?;
    created_app_authorizations.push(app_authorization);

  }
  
  let app_authorization_with_same_app_id = test_environment.create_random_app_authorization(Some(&created_app_authorizations[0].app_id)).await?;
  created_app_authorizations.push(app_authorization_with_same_app_id);

  let query = format!("app_id = \"{}\"", created_app_authorizations[0].app_id);
  let retrieved_app_authorizations = AppAuthorization::list(&query, &test_environment.database_pool, None).await?;

  let created_app_authorizations_with_specific_app_id: Vec<&AppAuthorization> = created_app_authorizations.iter().filter(|app_authorization| app_authorization.app_id == created_app_authorizations[0].app_id).collect();
  assert_eq!(created_app_authorizations_with_specific_app_id.len(), retrieved_app_authorizations.len());
  for i in 0..created_app_authorizations_with_specific_app_id.len() {

    let created_app_authorization = &created_app_authorizations_with_specific_app_id[i];
    let retrieved_app_authorization = &retrieved_app_authorizations[i];

    assert_app_authorizations_are_equal(created_app_authorization, retrieved_app_authorization);

  }

  return Ok(());

}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  const MAXIMUM_RESOURCE_COUNT: i32 = 25;
  let mut created_app_authorizations: Vec<AppAuthorization> = Vec::new();
  for _ in 0..MAXIMUM_RESOURCE_COUNT {

    let app_authorization = test_environment.create_random_app_authorization(None).await?;
    created_app_authorizations.push(app_authorization);

  }

  let retrieved_app_authorizations = AppAuthorization::list("", &test_environment.database_pool, None).await?;
  assert_eq!(created_app_authorizations.len(), retrieved_app_authorizations.len());
  for i in 0..created_app_authorizations.len() {

    let created_app_authorization = &created_app_authorizations[i];
    let retrieved_app_authorization = &retrieved_app_authorizations[i];

    assert_app_authorizations_are_equal(created_app_authorization, retrieved_app_authorization);

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
  let mut current_app_authorizations = AppAuthorization::list("", &test_environment.database_pool, None).await?;
  if current_app_authorizations.len() < MINIMUM_ACTION_COUNT as usize {

    let remaining_action_count = MINIMUM_ACTION_COUNT - current_app_authorizations.len() as i32;
    for _ in 0..remaining_action_count {

      let app_authorization = test_environment.create_random_app_authorization(None).await?;
      current_app_authorizations.push(app_authorization);

    }

  }

  // Get the "slashstep.appAuthorizations.get" action one time.
  let user = test_environment.create_random_user().await?;
  let get_app_authorizations_action = Action::get_by_name("slashstep.appAuthorizations.get", &test_environment.database_pool).await?;

  // Grant access to the "slashstep.appAuthorizations.get" action to the user for half of the actions.
  let allowed_action_count = current_app_authorizations.len() / 2;
  let mut allowed_app_authorizations = Vec::new();
  for index in 0..allowed_action_count {

    let scoped_app_authorization = &current_app_authorizations[index];

    AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: get_app_authorizations_action.id.clone(),
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::AppAuthorization,
      scoped_app_authorization_id: Some(scoped_app_authorization.id.clone()),
      ..Default::default()
    }, &test_environment.database_pool).await?;

    allowed_app_authorizations.push(scoped_app_authorization.clone());

  }

  // Make sure the user only sees the allowed actions.
  let individual_principal = crate::resources::access_policy::IndividualPrincipal::User(user.id);
  let retrieved_app_authorizations = AppAuthorization::list("", &test_environment.database_pool, Some(&individual_principal)).await?;

  assert_eq!(allowed_app_authorizations.len(), retrieved_app_authorizations.len());
  for allowed_app_authorization in allowed_app_authorizations {

    let retrieved_app_authorization = &retrieved_app_authorizations.iter().find(|action| action.id == allowed_app_authorization.id).unwrap();

    assert_app_authorizations_are_equal(&allowed_app_authorization, retrieved_app_authorization);

  }

  return Ok(());

}
