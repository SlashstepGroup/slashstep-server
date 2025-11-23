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
    AccessPolicy, AccessPolicyInheritanceLevel, AccessPolicyPermissionLevel, AccessPolicyPrincipalType, AccessPolicyScopedResourceType, InitialAccessPolicyProperties
  }, action::{Action, InitialActionProperties}, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, group::Group, item::Item, milestone::Milestone, project::Project, role::Role, user::{InitialUserProperties, User}, workspace::Workspace
};
use testcontainers_modules::{testcontainers::runners::SyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;

struct TestPostgresEnvironment {

  postgres_client: postgres::Client,
  postgres_container: testcontainers::Container<testcontainers_modules::postgres::Postgres>

}

fn create_test_postgres_environment<'a>() -> TestPostgresEnvironment {

  let postgres_container = testcontainers_modules::postgres::Postgres::default()
    .with_tag("18")
    .start()
    .unwrap();
  let postgres_host = postgres_container.get_host().unwrap();
  let postgres_port = postgres_container.get_host_port_ipv4(5432).unwrap();
  let postgres_connection_string = format!("postgres://postgres:postgres@{}:{}", postgres_host, postgres_port);
  let postgres_client = postgres::Client::connect(&postgres_connection_string, postgres::NoTls).unwrap();

  return TestPostgresEnvironment {
    postgres_client,
    postgres_container
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

#[test]
fn create_access_policy() {

  let mut test_postgres_environment = create_test_postgres_environment();
  initialize_required_tables(&mut test_postgres_environment.postgres_client);

  // Create the access policy.
  let action = create_random_action(&mut test_postgres_environment.postgres_client);
  let user = create_random_user(&mut test_postgres_environment.postgres_client);
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
  let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_postgres_environment.postgres_client).unwrap();

  // Ensure that all the properties were set correctly.
  assert_eq!(access_policy.action_id, access_policy_properties.action_id);
  assert_eq!(access_policy.permission_level, access_policy_properties.permission_level);
  assert_eq!(access_policy.inheritance_level, access_policy_properties.inheritance_level);
  assert_eq!(access_policy.principal_type, access_policy_properties.principal_type);
  assert_eq!(access_policy.principal_user_id, access_policy_properties.principal_user_id);
  assert_eq!(access_policy.principal_group_id, access_policy_properties.principal_group_id);
  assert_eq!(access_policy.principal_role_id, access_policy_properties.principal_role_id);
  assert_eq!(access_policy.principal_app_id, access_policy_properties.principal_app_id);
  assert_eq!(access_policy.scoped_resource_type, access_policy_properties.scoped_resource_type);
  assert_eq!(access_policy.scoped_action_id, access_policy_properties.scoped_action_id);
  assert_eq!(access_policy.scoped_app_id, access_policy_properties.scoped_app_id);
  assert_eq!(access_policy.scoped_group_id, access_policy_properties.scoped_group_id);
  assert_eq!(access_policy.scoped_item_id, access_policy_properties.scoped_item_id);
  assert_eq!(access_policy.scoped_milestone_id, access_policy_properties.scoped_milestone_id);
  assert_eq!(access_policy.scoped_project_id, access_policy_properties.scoped_project_id);
  assert_eq!(access_policy.scoped_role_id, access_policy_properties.scoped_role_id);
  assert_eq!(access_policy.scoped_user_id, access_policy_properties.scoped_user_id);

}
