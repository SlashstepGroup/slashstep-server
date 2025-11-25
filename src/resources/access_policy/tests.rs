/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use crate::resources::{
  access_policy::{
    AccessPolicy, 
    AccessPolicyInheritanceLevel, 
    AccessPolicyPermissionLevel, 
    AccessPolicyPrincipalType, 
    AccessPolicyScopedResourceType, 
    DEFAULT_ACCESS_POLICY_LIST_LIMIT, 
    InitialAccessPolicyProperties
  }, 
  action::{Action, InitialActionProperties}, 
  app::App, 
  app_authorization::AppAuthorization, 
  app_authorization_credential::AppAuthorizationCredential, 
  app_credential::AppCredential, 
  group::Group, 
  item::Item, 
  milestone::Milestone, 
  project::Project, 
  role::Role, 
  user::{InitialUserProperties, User}, 
  workspace::Workspace
};
use testcontainers_modules::{testcontainers::runners::SyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;

struct TestPostgresEnvironment {
  
  postgres_client: postgres::Client,

  // This is required to prevent the compiler from complaining about unused fields.
  // We need a wrapper struct to fix lifetime issues, but we don't need to use the container for any test right now.
  #[allow(dead_code)]
  postgres_container: testcontainers::Container<testcontainers_modules::postgres::Postgres>

}

fn create_test_postgres_environment() -> TestPostgresEnvironment {

  let postgres_container = testcontainers_modules::postgres::Postgres::default()
    .with_tag("18")
    .start()
    .unwrap();
  let postgres_host = postgres_container.get_host().unwrap();
  let postgres_port = postgres_container.get_host_port_ipv4(5432).unwrap();
  let postgres_connection_string = format!("postgres://postgres:postgres@{}:{}", postgres_host, postgres_port);
  let mut postgres_client = postgres::Client::connect(&postgres_connection_string, postgres::NoTls).unwrap();
  initialize_required_tables(&mut postgres_client);

  return TestPostgresEnvironment {
    postgres_client,
    postgres_container: postgres_container
  };

}

fn create_random_action(postgres_client: &mut postgres::Client) -> Action {

  let action_properties = InitialActionProperties {
    name: Uuid::now_v7().to_string(),
    display_name: Uuid::now_v7().to_string(),
    description: Uuid::now_v7().to_string(),
    app_id: None
  };

  let action = Action::create(&action_properties, postgres_client).unwrap();

  return action;

}

fn create_random_user(postgres_client: &mut postgres::Client) -> User {

  let user_properties = InitialUserProperties {
    username: Some(Uuid::now_v7().to_string()),
    display_name: Some(Uuid::now_v7().to_string()),
    hashed_password: Some(Uuid::now_v7().to_string()),
    is_anonymous: false,
    ip_address: None
  };

  let user = User::create(&user_properties, postgres_client).unwrap();

  return user;

}

fn initialize_required_tables(postgres_client: &mut postgres::Client) {

  // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
  User::initialize_users_table(postgres_client).unwrap();
  Group::initialize_groups_table(postgres_client).unwrap();
  App::initialize_apps_table(postgres_client).unwrap();
  Workspace::initialize_workspaces_table(postgres_client).unwrap();
  Project::initialize_projects_table(postgres_client).unwrap();
  Role::initialize_roles_table(postgres_client).unwrap();
  Item::initialize_items_table(postgres_client).unwrap();
  Action::initialize_actions_table(postgres_client).unwrap();
  AppCredential::initialize_app_credentials_table(postgres_client).unwrap();
  AppAuthorization::initialize_app_authorizations_table(postgres_client).unwrap();
  AppAuthorizationCredential::initialize_app_authorization_credentials_table(postgres_client).unwrap();
  Milestone::initialize_milestones_table(postgres_client).unwrap();
  AccessPolicy::initialize_access_policies_table(postgres_client).unwrap();

}

fn assert_access_policy_is_equal_to_initial_properties(access_policy: &AccessPolicy, initial_properties: &InitialAccessPolicyProperties) {

  assert_eq!(access_policy.action_id, initial_properties.action_id);
  assert_eq!(access_policy.permission_level, initial_properties.permission_level);
  assert_eq!(access_policy.inheritance_level, initial_properties.inheritance_level);
  assert_eq!(access_policy.principal_type, initial_properties.principal_type);
  assert_eq!(access_policy.principal_user_id, initial_properties.principal_user_id);
  assert_eq!(access_policy.principal_group_id, initial_properties.principal_group_id);
  assert_eq!(access_policy.principal_role_id, initial_properties.principal_role_id);
  assert_eq!(access_policy.principal_app_id, initial_properties.principal_app_id);
  assert_eq!(access_policy.scoped_resource_type, initial_properties.scoped_resource_type);
  assert_eq!(access_policy.scoped_action_id, initial_properties.scoped_action_id);
  assert_eq!(access_policy.scoped_app_id, initial_properties.scoped_app_id);
  assert_eq!(access_policy.scoped_group_id, initial_properties.scoped_group_id);
  assert_eq!(access_policy.scoped_item_id, initial_properties.scoped_item_id);
  assert_eq!(access_policy.scoped_milestone_id, initial_properties.scoped_milestone_id);
  assert_eq!(access_policy.scoped_project_id, initial_properties.scoped_project_id);
  assert_eq!(access_policy.scoped_role_id, initial_properties.scoped_role_id);
  assert_eq!(access_policy.scoped_user_id, initial_properties.scoped_user_id);

}

fn assert_access_policies_are_equal(access_policy_1: &AccessPolicy, access_policy_2: &AccessPolicy) {

  assert_eq!(access_policy_1.id, access_policy_2.id);
  assert_eq!(access_policy_1.action_id, access_policy_2.action_id);
  assert_eq!(access_policy_1.permission_level, access_policy_2.permission_level);
  assert_eq!(access_policy_1.inheritance_level, access_policy_2.inheritance_level);
  assert_eq!(access_policy_1.principal_type, access_policy_2.principal_type);
  assert_eq!(access_policy_1.principal_user_id, access_policy_2.principal_user_id);
  assert_eq!(access_policy_1.principal_group_id, access_policy_2.principal_group_id);
  assert_eq!(access_policy_1.principal_role_id, access_policy_2.principal_role_id);
  assert_eq!(access_policy_1.principal_app_id, access_policy_2.principal_app_id);
  assert_eq!(access_policy_1.scoped_resource_type, access_policy_2.scoped_resource_type);
  assert_eq!(access_policy_1.scoped_action_id, access_policy_2.scoped_action_id);
  assert_eq!(access_policy_1.scoped_app_id, access_policy_2.scoped_app_id);
  assert_eq!(access_policy_1.scoped_group_id, access_policy_2.scoped_group_id);
  assert_eq!(access_policy_1.scoped_item_id, access_policy_2.scoped_item_id);
  assert_eq!(access_policy_1.scoped_milestone_id, access_policy_2.scoped_milestone_id);
  assert_eq!(access_policy_1.scoped_project_id, access_policy_2.scoped_project_id);
  assert_eq!(access_policy_1.scoped_role_id, access_policy_2.scoped_role_id);
  assert_eq!(access_policy_1.scoped_user_id, access_policy_2.scoped_user_id);

}

/// Verifies that an access_policies table can be initialized.
#[test]
fn initialize_access_policies_table() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  AccessPolicy::initialize_access_policies_table(&mut postgres_client).unwrap();

}

/// Verifies that an access policy can be created.
#[test]
fn create_access_policy() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  // Create the access policy.
  let action = create_random_action(&mut postgres_client);
  let user = create_random_user(&mut postgres_client);
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    inheritance_level: AccessPolicyInheritanceLevel::Enabled,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    principal_group_id: None,
    principal_role_id: None,
    principal_app_id: None,
    scoped_resource_type: AccessPolicyScopedResourceType::Instance,
    scoped_action_id: None,
    scoped_app_id: None,
    scoped_group_id: None,
    scoped_item_id: None,
    scoped_milestone_id: None,
    scoped_project_id: None,
    scoped_role_id: None,
    scoped_user_id: None,
    scoped_workspace_id: None
  };
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();

  // Ensure that all the properties were set correctly.
  assert_access_policy_is_equal_to_initial_properties(&access_policy, &access_policy_properties);

}

/// Verifies that an access policy can be retrieved by its ID.
#[test]
fn get_access_policy_by_id() {

  // Create the access policy.
  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  let action = create_random_action(&mut postgres_client);
  let user = create_random_user(&mut postgres_client);
  let access_policy_properties = InitialAccessPolicyProperties {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    inheritance_level: AccessPolicyInheritanceLevel::Enabled,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    principal_group_id: None,
    principal_role_id: None,
    principal_app_id: None,
    scoped_resource_type: AccessPolicyScopedResourceType::Instance,
    scoped_action_id: None,
    scoped_app_id: None,
    scoped_group_id: None,
    scoped_item_id: None,
    scoped_milestone_id: None,
    scoped_project_id: None,
    scoped_role_id: None,
    scoped_user_id: None,
    scoped_workspace_id: None
  };
  let created_access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();
  let retrieved_access_policy = AccessPolicy::get_by_id(&created_access_policy.id, &mut postgres_client).unwrap();

  assert_access_policies_are_equal(&created_access_policy, &retrieved_access_policy);

}

/// Verifies that a list of access policies can be retrieved without a query.
#[test]
fn list_access_policies_without_query() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  const MAXIMUM_ACTION_COUNT: i32 = 25;
  let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
  let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
  while remaining_action_count > 0 {

    let action = create_random_action(&mut postgres_client);
    let user = create_random_user(&mut postgres_client);
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: AccessPolicyPermissionLevel::User,
      inheritance_level: AccessPolicyInheritanceLevel::Enabled,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id),
      principal_group_id: None,
      principal_role_id: None,
      principal_app_id: None,
      scoped_resource_type: AccessPolicyScopedResourceType::Instance,
      scoped_action_id: None,
      scoped_app_id: None,
      scoped_group_id: None,
      scoped_item_id: None,
      scoped_milestone_id: None,
      scoped_project_id: None,
      scoped_role_id: None,
      scoped_user_id: None,
      scoped_workspace_id: None
    };
    let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();
    created_access_policies.push(access_policy);
    remaining_action_count -= 1;

  }

  let retrieved_access_policies = AccessPolicy::list("", &mut postgres_client).unwrap();

  assert_eq!(created_access_policies.len(), retrieved_access_policies.len());
  for i in 0..created_access_policies.len() {

    let created_access_policy = &created_access_policies[i];
    let retrieved_access_policy = &retrieved_access_policies[i];

    assert_access_policies_are_equal(created_access_policy, retrieved_access_policy);

  }

}

/// Verifies that a list of access policies can be retrieved with a query.
#[test]
fn list_access_policies_with_query() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  const MAXIMUM_ACTION_COUNT: i32 = 5;
  let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
  let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
  while remaining_action_count > 0 {

    let action = create_random_action(&mut postgres_client);
    let user = create_random_user(&mut postgres_client);
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: AccessPolicyPermissionLevel::User,
      inheritance_level: AccessPolicyInheritanceLevel::Enabled,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: if remaining_action_count == 1 { created_access_policies[0].principal_user_id } else { Some(user.id) },
      principal_group_id: None,
      principal_role_id: None,
      principal_app_id: None,
      scoped_resource_type: AccessPolicyScopedResourceType::Instance,
      scoped_action_id: None,
      scoped_app_id: None,
      scoped_group_id: None,
      scoped_item_id: None,
      scoped_milestone_id: None,
      scoped_project_id: None,
      scoped_role_id: None,
      scoped_user_id: None,
      scoped_workspace_id: None
    };
    let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();
    created_access_policies.push(access_policy);
    remaining_action_count -= 1;

  }

  let query = format!("principal_user_id = \"{}\"", created_access_policies[0].principal_user_id.unwrap());
  let retrieved_access_policies = AccessPolicy::list(&query, &mut postgres_client).unwrap();

  let created_access_policies_with_specific_user: Vec<&AccessPolicy> = created_access_policies.iter().filter(|access_policy| access_policy.principal_user_id == Some(created_access_policies[0].principal_user_id.unwrap())).collect();
  assert_eq!(created_access_policies_with_specific_user.len(), retrieved_access_policies.len());
  for i in 0..created_access_policies_with_specific_user.len() {

    let created_access_policy = &created_access_policies_with_specific_user[i];
    let retrieved_access_policy = &retrieved_access_policies[i];

    assert_access_policies_are_equal(created_access_policy, retrieved_access_policy);

  }

}

/// Verifies that the implementation can return up to a maximum number of access policies by default.
#[test]
fn list_access_policies_with_default_limit() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1;
  let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
  let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
  while remaining_action_count > 0 {

    let action = create_random_action(&mut postgres_client);
    let user = create_random_user(&mut postgres_client);
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: AccessPolicyPermissionLevel::User,
      inheritance_level: AccessPolicyInheritanceLevel::Enabled,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id),
      principal_group_id: None,
      principal_role_id: None,
      principal_app_id: None,
      scoped_resource_type: AccessPolicyScopedResourceType::Instance,
      scoped_action_id: None,
      scoped_app_id: None,
      scoped_group_id: None,
      scoped_item_id: None,
      scoped_milestone_id: None,
      scoped_project_id: None,
      scoped_role_id: None,
      scoped_user_id: None,
      scoped_workspace_id: None
    };
    let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();
    created_access_policies.push(access_policy);
    remaining_action_count -= 1;

  }

  let retrieved_access_policies = AccessPolicy::list("", &mut postgres_client).unwrap();

  assert_eq!(retrieved_access_policies.len(), DEFAULT_ACCESS_POLICY_LIST_LIMIT as usize);
  
}

/// Verifies that the implementation can return an accurate count of access policies.
#[test]
fn count_access_policies() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1;
  let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
  let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
  while remaining_action_count > 0 {

    let action = create_random_action(&mut postgres_client);
    let user = create_random_user(&mut postgres_client);
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: AccessPolicyPermissionLevel::User,
      inheritance_level: AccessPolicyInheritanceLevel::Enabled,
      principal_type: AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id),
      principal_group_id: None,
      principal_role_id: None,
      principal_app_id: None,
      scoped_resource_type: AccessPolicyScopedResourceType::Instance,
      scoped_action_id: None,
      scoped_app_id: None,
      scoped_group_id: None,
      scoped_item_id: None,
      scoped_milestone_id: None,
      scoped_project_id: None,
      scoped_role_id: None,
      scoped_user_id: None,
      scoped_workspace_id: None
    };
    let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).unwrap();
    created_access_policies.push(access_policy);
    remaining_action_count -= 1;

  }

  let retrieved_access_policy_count = AccessPolicy::count("", &mut postgres_client).unwrap();

  assert_eq!(retrieved_access_policy_count, MAXIMUM_ACTION_COUNT);

}

/// Verifies that the implementation can return a list of access policies in the proper order given a hierarchy.
#[test]
fn list_access_policies_by_hierarchy() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  // Create the access policy.
  let action = create_random_action(&mut postgres_client);
  let user = create_random_user(&mut postgres_client);
  let instance_access_policy_properties = InitialAccessPolicyProperties {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    inheritance_level: AccessPolicyInheritanceLevel::Enabled,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    principal_group_id: None,
    principal_role_id: None,
    principal_app_id: None,
    scoped_resource_type: AccessPolicyScopedResourceType::Instance,
    scoped_action_id: None,
    scoped_app_id: None,
    scoped_group_id: None,
    scoped_item_id: None,
    scoped_milestone_id: None,
    scoped_project_id: None,
    scoped_role_id: None,
    scoped_user_id: None,
    scoped_workspace_id: None
  };
  let instance_access_policy = AccessPolicy::create(&instance_access_policy_properties, &mut postgres_client).unwrap();
  let access_policy_hierarchy = vec![(&instance_access_policy.scoped_resource_type, None)];

  let retrieved_access_policies = AccessPolicy::list_by_hierarchy(&access_policy_hierarchy, &action.id, &mut postgres_client).unwrap();

  assert_eq!(retrieved_access_policies.len(), access_policy_hierarchy.len());

}

/// Verifies that the implementation can delete an access policy.
#[test]
fn delete_access_policy() {

  let test_postgres_environment = create_test_postgres_environment();
  let mut postgres_client = test_postgres_environment.postgres_client;

  // Create the access policy.
  let action = create_random_action(&mut postgres_client);
  let user = create_random_user(&mut postgres_client);
  let instance_access_policy_properties = InitialAccessPolicyProperties {
    action_id: action.id,
    permission_level: AccessPolicyPermissionLevel::User,
    inheritance_level: AccessPolicyInheritanceLevel::Enabled,
    principal_type: AccessPolicyPrincipalType::User,
    principal_user_id: Some(user.id),
    principal_group_id: None,
    principal_role_id: None,
    principal_app_id: None,
    scoped_resource_type: AccessPolicyScopedResourceType::Instance,
    scoped_action_id: None,
    scoped_app_id: None,
    scoped_group_id: None,
    scoped_item_id: None,
    scoped_milestone_id: None,
    scoped_project_id: None,
    scoped_role_id: None,
    scoped_user_id: None,
    scoped_workspace_id: None
  };
  let instance_access_policy = AccessPolicy::create(&instance_access_policy_properties, &mut postgres_client).unwrap();

  instance_access_policy.delete(&mut postgres_client).unwrap();

  // Ensure that the access policy is no longer in the database.
  let retrieved_access_policy_result = AccessPolicy::get_by_id(&instance_access_policy.id, &mut postgres_client);
  assert!(retrieved_access_policy_result.is_err());

}

/// Verifies that the implementation can update an access policy.
#[test]
fn update_access_policy() {

}
