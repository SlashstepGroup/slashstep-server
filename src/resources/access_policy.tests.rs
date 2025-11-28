// /**
//  * 
//  * This module contains tests for the access_policy module.
//  * 
//  * Programmers: 
//  * - Christian Toney (https://christiantoney.com)
//  * 
//  * © 2025 Beastslash LLC
//  * 
//  */

// use crate::{initialize_required_tables, resources::access_policy::{
//     AccessPolicy, 
//     AccessPolicyInheritanceLevel, 
//     AccessPolicyPermissionLevel, 
//     AccessPolicyPrincipalType, 
//     AccessPolicyScopedResourceType, 
//     DEFAULT_ACCESS_POLICY_LIST_LIMIT, 
//     EditableAccessPolicyProperties, 
//     InitialAccessPolicyProperties
//   }, tests::TestEnvironment};
// use anyhow::{anyhow, Result};

// fn assert_access_policy_is_equal_to_initial_properties(access_policy: &AccessPolicy, initial_properties: &InitialAccessPolicyProperties) {

//   assert_eq!(access_policy.action_id, initial_properties.action_id);
//   assert_eq!(access_policy.permission_level, initial_properties.permission_level);
//   assert_eq!(access_policy.inheritance_level, initial_properties.inheritance_level);
//   assert_eq!(access_policy.principal_type, initial_properties.principal_type);
//   assert_eq!(access_policy.principal_user_id, initial_properties.principal_user_id);
//   assert_eq!(access_policy.principal_group_id, initial_properties.principal_group_id);
//   assert_eq!(access_policy.principal_role_id, initial_properties.principal_role_id);
//   assert_eq!(access_policy.principal_app_id, initial_properties.principal_app_id);
//   assert_eq!(access_policy.scoped_resource_type, initial_properties.scoped_resource_type);
//   assert_eq!(access_policy.scoped_action_id, initial_properties.scoped_action_id);
//   assert_eq!(access_policy.scoped_app_id, initial_properties.scoped_app_id);
//   assert_eq!(access_policy.scoped_group_id, initial_properties.scoped_group_id);
//   assert_eq!(access_policy.scoped_item_id, initial_properties.scoped_item_id);
//   assert_eq!(access_policy.scoped_milestone_id, initial_properties.scoped_milestone_id);
//   assert_eq!(access_policy.scoped_project_id, initial_properties.scoped_project_id);
//   assert_eq!(access_policy.scoped_role_id, initial_properties.scoped_role_id);
//   assert_eq!(access_policy.scoped_user_id, initial_properties.scoped_user_id);

// }

// fn assert_access_policies_are_equal(access_policy_1: &AccessPolicy, access_policy_2: &AccessPolicy) {

//   assert_eq!(access_policy_1.id, access_policy_2.id);
//   assert_eq!(access_policy_1.action_id, access_policy_2.action_id);
//   assert_eq!(access_policy_1.permission_level, access_policy_2.permission_level);
//   assert_eq!(access_policy_1.inheritance_level, access_policy_2.inheritance_level);
//   assert_eq!(access_policy_1.principal_type, access_policy_2.principal_type);
//   assert_eq!(access_policy_1.principal_user_id, access_policy_2.principal_user_id);
//   assert_eq!(access_policy_1.principal_group_id, access_policy_2.principal_group_id);
//   assert_eq!(access_policy_1.principal_role_id, access_policy_2.principal_role_id);
//   assert_eq!(access_policy_1.principal_app_id, access_policy_2.principal_app_id);
//   assert_eq!(access_policy_1.scoped_resource_type, access_policy_2.scoped_resource_type);
//   assert_eq!(access_policy_1.scoped_action_id, access_policy_2.scoped_action_id);
//   assert_eq!(access_policy_1.scoped_app_id, access_policy_2.scoped_app_id);
//   assert_eq!(access_policy_1.scoped_group_id, access_policy_2.scoped_group_id);
//   assert_eq!(access_policy_1.scoped_item_id, access_policy_2.scoped_item_id);
//   assert_eq!(access_policy_1.scoped_milestone_id, access_policy_2.scoped_milestone_id);
//   assert_eq!(access_policy_1.scoped_project_id, access_policy_2.scoped_project_id);
//   assert_eq!(access_policy_1.scoped_role_id, access_policy_2.scoped_role_id);
//   assert_eq!(access_policy_1.scoped_user_id, access_policy_2.scoped_user_id);

// }

// /// Verifies that an access_policies table can be initialized.
// #[tokio::test]
// async fn initialize_access_policies_table() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;

//   return Ok(());

// }

// /// Verifies that an access policy can be created.
// #[tokio::test]
// async fn create_access_policy() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;

//   // Create the access policy.
//   let action = test_environment.create_random_action().await?;
//   let user = test_environment.create_random_user().await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: action.id,
//     permission_level: AccessPolicyPermissionLevel::User,
//     inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     principal_group_id: None,
//     principal_role_id: None,
//     principal_app_id: None,
//     scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//     scoped_action_id: None,
//     scoped_app_id: None,
//     scoped_group_id: None,
//     scoped_item_id: None,
//     scoped_milestone_id: None,
//     scoped_project_id: None,
//     scoped_role_id: None,
//     scoped_user_id: None,
//     scoped_workspace_id: None
//   };
//   let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;

//   // Ensure that all the properties were set correctly.
//   assert_access_policy_is_equal_to_initial_properties(&access_policy, &access_policy_properties);

//   return Ok(());

// }

// /// Verifies that an access policy can be retrieved by its ID.
// #[tokio::test]
// async fn get_access_policy_by_id() -> Result<()> {

//   // Create the access policy.
//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;
//   let action = test_environment.create_random_action().await?;
//   let user = test_environment.create_random_user().await?;
//   let access_policy_properties = InitialAccessPolicyProperties {
//     action_id: action.id,
//     permission_level: AccessPolicyPermissionLevel::User,
//     inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     principal_group_id: None,
//     principal_role_id: None,
//     principal_app_id: None,
//     scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//     scoped_action_id: None,
//     scoped_app_id: None,
//     scoped_group_id: None,
//     scoped_item_id: None,
//     scoped_milestone_id: None,
//     scoped_project_id: None,
//     scoped_role_id: None,
//     scoped_user_id: None,
//     scoped_workspace_id: None
//   };
//   let created_access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;
//   let retrieved_access_policy = AccessPolicy::get_by_id(&created_access_policy.id, &mut test_environment.postgres_client).await?;

//   assert_access_policies_are_equal(&created_access_policy, &retrieved_access_policy);

//   return Ok(());

// }

// /// Verifies that a list of access policies can be retrieved without a query.
// #[tokio::test]
// async fn list_access_policies_without_query() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;
//   const MAXIMUM_ACTION_COUNT: i32 = 25;
//   let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
//   let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
//   while remaining_action_count > 0 {

//     let action = test_environment.create_random_action().await?;
//     let user = test_environment.create_random_user().await?;
//     let access_policy_properties = InitialAccessPolicyProperties {
//       action_id: action.id,
//       permission_level: AccessPolicyPermissionLevel::User,
//       inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//       principal_type: AccessPolicyPrincipalType::User,
//       principal_user_id: Some(user.id),
//       principal_group_id: None,
//       principal_role_id: None,
//       principal_app_id: None,
//       scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//       scoped_action_id: None,
//       scoped_app_id: None,
//       scoped_group_id: None,
//       scoped_item_id: None,
//       scoped_milestone_id: None,
//       scoped_project_id: None,
//       scoped_role_id: None,
//       scoped_user_id: None,
//       scoped_workspace_id: None
//     };
//     let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;
//     created_access_policies.push(access_policy);
//     remaining_action_count -= 1;

//   }

//   let retrieved_access_policies = AccessPolicy::list("", &mut test_environment.postgres_client).await?;

//   assert_eq!(created_access_policies.len(), retrieved_access_policies.len());
//   for i in 0..created_access_policies.len() {

//     let created_access_policy = &created_access_policies[i];
//     let retrieved_access_policy = &retrieved_access_policies[i];

//     assert_access_policies_are_equal(created_access_policy, retrieved_access_policy);

//   }

//   return Ok(());

// }

// /// Verifies that a list of access policies can be retrieved with a query.
// #[tokio::test]
// async fn list_access_policies_with_query() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;
//   const MAXIMUM_ACTION_COUNT: i32 = 5;
//   let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
//   let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
//   while remaining_action_count > 0 {

//     let action = test_environment.create_random_action().await?;
//     let user = test_environment.create_random_user().await?;
//     let access_policy_properties = InitialAccessPolicyProperties {
//       action_id: action.id,
//       permission_level: AccessPolicyPermissionLevel::User,
//       inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//       principal_type: AccessPolicyPrincipalType::User,
//       principal_user_id: if remaining_action_count == 1 { created_access_policies[0].principal_user_id } else { Some(user.id) },
//       principal_group_id: None,
//       principal_role_id: None,
//       principal_app_id: None,
//       scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//       scoped_action_id: None,
//       scoped_app_id: None,
//       scoped_group_id: None,
//       scoped_item_id: None,
//       scoped_milestone_id: None,
//       scoped_project_id: None,
//       scoped_role_id: None,
//       scoped_user_id: None,
//       scoped_workspace_id: None
//     };
//     let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;
//     created_access_policies.push(access_policy);
//     remaining_action_count -= 1;


//   }

//   let principal_user_id = created_access_policies[0].principal_user_id.ok_or_else(|| anyhow!("Principal user ID is not set."))?;
//   let query = format!("principal_user_id = \"{}\"", principal_user_id);
//   let retrieved_access_policies = AccessPolicy::list(&query, &mut test_environment.postgres_client).await?;

//   let created_access_policies_with_specific_user: Vec<&AccessPolicy> = created_access_policies.iter().filter(|access_policy| access_policy.principal_user_id == Some(principal_user_id)).collect();
//   assert_eq!(created_access_policies_with_specific_user.len(), retrieved_access_policies.len());
//   for i in 0..created_access_policies_with_specific_user.len() {

//     let created_access_policy = &created_access_policies_with_specific_user[i];
//     let retrieved_access_policy = &retrieved_access_policies[i];

//     assert_access_policies_are_equal(created_access_policy, retrieved_access_policy);

//   }

//   return Ok(());

// }

// /// Verifies that the implementation can return up to a maximum number of access policies by default.
// #[tokio::test]
// async fn list_access_policies_with_default_limit() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;
//   const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1;
//   let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
//   let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
//   while remaining_action_count > 0 {

//     let action = test_environment.create_random_action().await?;
//     let user = test_environment.create_random_user().await?;
//     let access_policy_properties = InitialAccessPolicyProperties {
//       action_id: action.id,
//       permission_level: AccessPolicyPermissionLevel::User,
//       inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//       principal_type: AccessPolicyPrincipalType::User,
//       principal_user_id: Some(user.id),
//       principal_group_id: None,
//       principal_role_id: None,
//       principal_app_id: None,
//       scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//       scoped_action_id: None,
//       scoped_app_id: None,
//       scoped_group_id: None,
//       scoped_item_id: None,
//       scoped_milestone_id: None,
//       scoped_project_id: None,
//       scoped_role_id: None,
//       scoped_user_id: None,
//       scoped_workspace_id: None
//     };
//     let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;
//     created_access_policies.push(access_policy);
//     remaining_action_count -= 1;

//   }

//   let retrieved_access_policies = AccessPolicy::list("", &mut test_environment.postgres_client).await?;

//   assert_eq!(retrieved_access_policies.len(), DEFAULT_ACCESS_POLICY_LIST_LIMIT as usize);

//   return Ok(());
  
// }

// /// Verifies that the implementation can return an accurate count of access policies.
// #[tokio::test]
// async fn count_access_policies() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;
//   const MAXIMUM_ACTION_COUNT: i64 = DEFAULT_ACCESS_POLICY_LIST_LIMIT + 1;
//   let mut created_access_policies: Vec<AccessPolicy> = Vec::new();
//   let mut remaining_action_count = MAXIMUM_ACTION_COUNT;
//   while remaining_action_count > 0 {

//     let action = test_environment.create_random_action().await?;
//     let user = test_environment.create_random_user().await?;
//     let access_policy_properties = InitialAccessPolicyProperties {
//       action_id: action.id,
//       permission_level: AccessPolicyPermissionLevel::User,
//       inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//       principal_type: AccessPolicyPrincipalType::User,
//       principal_user_id: Some(user.id),
//       principal_group_id: None,
//       principal_role_id: None,
//       principal_app_id: None,
//       scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//       scoped_action_id: None,
//       scoped_app_id: None,
//       scoped_group_id: None,
//       scoped_item_id: None,
//       scoped_milestone_id: None,
//       scoped_project_id: None,
//       scoped_role_id: None,
//       scoped_user_id: None,
//       scoped_workspace_id: None
//     };
//     let access_policy = AccessPolicy::create(&access_policy_properties, &mut test_environment.postgres_client).await?;
//     created_access_policies.push(access_policy);
//     remaining_action_count -= 1;

//   }

//   let retrieved_access_policy_count = AccessPolicy::count("", &mut test_environment.postgres_client).await?;

//   assert_eq!(retrieved_access_policy_count, MAXIMUM_ACTION_COUNT);

//   return Ok(());

// }

// /// Verifies that the implementation can return a list of access policies in the proper order given a hierarchy.
// #[tokio::test]
// async fn list_access_policies_by_hierarchy() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;

//   // Create the access policy.
//   let action = test_environment.create_random_action().await?;
//   let user = test_environment.create_random_user().await?;
//   let instance_access_policy_properties = InitialAccessPolicyProperties {
//     action_id: action.id,
//     permission_level: AccessPolicyPermissionLevel::User,
//     inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     principal_group_id: None,
//     principal_role_id: None,
//     principal_app_id: None,
//     scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//     scoped_action_id: None,
//     scoped_app_id: None,
//     scoped_group_id: None,
//     scoped_item_id: None,
//     scoped_milestone_id: None,
//     scoped_project_id: None,
//     scoped_role_id: None,
//     scoped_user_id: None,
//     scoped_workspace_id: None
//   };
//   let instance_access_policy = AccessPolicy::create(&instance_access_policy_properties, &mut test_environment.postgres_client).await?;
//   let access_policy_hierarchy = vec![(&instance_access_policy.scoped_resource_type, None)];

//   let retrieved_access_policies = AccessPolicy::list_by_hierarchy(&access_policy_hierarchy, &action.id, &mut test_environment.postgres_client).await?;

//   assert_eq!(retrieved_access_policies.len(), access_policy_hierarchy.len());
  
//   return Ok(());

// }

// /// Verifies that the implementation can delete an access policy.
// #[tokio::test]
// async fn delete_access_policy() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;

//   // Create the access policy.
//   let action = test_environment.create_random_action().await?;
//   let user = test_environment.create_random_user().await?;
//   let instance_access_policy_properties = InitialAccessPolicyProperties {
//     action_id: action.id,
//     permission_level: AccessPolicyPermissionLevel::User,
//     inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     principal_group_id: None,
//     principal_role_id: None,
//     principal_app_id: None,
//     scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//     scoped_action_id: None,
//     scoped_app_id: None,
//     scoped_group_id: None,
//     scoped_item_id: None,
//     scoped_milestone_id: None,
//     scoped_project_id: None,
//     scoped_role_id: None,
//     scoped_user_id: None,
//     scoped_workspace_id: None
//   };
//   let instance_access_policy = AccessPolicy::create(&instance_access_policy_properties, &mut test_environment.postgres_client).await?;

//   instance_access_policy.delete(&mut test_environment.postgres_client).await?;

//   // Ensure that the access policy is no longer in the database.
//   let retrieved_access_policy_result = AccessPolicy::get_by_id(&instance_access_policy.id, &mut test_environment.postgres_client).await;
//   assert!(retrieved_access_policy_result.is_err());

//   return Ok(());

// }

// /// Verifies that the implementation can update an access policy.
// #[tokio::test]
// async fn update_access_policy() -> Result<()> {

//   let mut test_environment = TestEnvironment::new().await?;
//   initialize_required_tables(&mut test_environment.postgres_client).await?;

//   // Create the access policy.
//   let action = test_environment.create_random_action().await?;
//   let user = test_environment.create_random_user().await?;
//   let instance_access_policy_properties = InitialAccessPolicyProperties {
//     action_id: action.id,
//     permission_level: AccessPolicyPermissionLevel::User,
//     inheritance_level: AccessPolicyInheritanceLevel::Enabled,
//     principal_type: AccessPolicyPrincipalType::User,
//     principal_user_id: Some(user.id),
//     principal_group_id: None,
//     principal_role_id: None,
//     principal_app_id: None,
//     scoped_resource_type: AccessPolicyScopedResourceType::Instance,
//     scoped_action_id: None,
//     scoped_app_id: None,
//     scoped_group_id: None,
//     scoped_item_id: None,
//     scoped_milestone_id: None,
//     scoped_project_id: None,
//     scoped_role_id: None,
//     scoped_user_id: None,
//     scoped_workspace_id: None
//   };
//   let instance_access_policy = AccessPolicy::create(&instance_access_policy_properties, &mut test_environment.postgres_client).await?;
//   let updated_access_policy_properties = EditableAccessPolicyProperties {
//     permission_level: Some(AccessPolicyPermissionLevel::Editor),
//     inheritance_level: Some(AccessPolicyInheritanceLevel::Disabled)
//   };
//   let updated_access_policy = instance_access_policy.update(&updated_access_policy_properties, &mut test_environment.postgres_client).await?;

//   assert_eq!(updated_access_policy.permission_level, AccessPolicyPermissionLevel::Editor);
//   assert_eq!(updated_access_policy.inheritance_level, AccessPolicyInheritanceLevel::Disabled);

//   return Ok(());

// }
