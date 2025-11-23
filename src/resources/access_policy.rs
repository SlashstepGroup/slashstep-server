/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use core::{fmt};
use std::str::FromStr;
use postgres::{error::SqlState, types::ToSql};
use postgres_types::FromSql;
use uuid::Uuid;
use crate::errors::resource_already_exists_error::{ResourceAlreadyExistsError};

#[derive(Debug, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "permission_level")]
pub enum AccessPolicyPermissionLevel {
  None,
  User,
  Editor,
  Admin
}

impl fmt::Display for AccessPolicyPermissionLevel {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyPermissionLevel::None => write!(f, "None"),
      AccessPolicyPermissionLevel::User => write!(f, "User"),
      AccessPolicyPermissionLevel::Editor => write!(f, "Editor"),
      AccessPolicyPermissionLevel::Admin => write!(f, "Admin")
    }
  }
}

impl FromStr for AccessPolicyPermissionLevel {

  type Err = String;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "None" => Ok(AccessPolicyPermissionLevel::None),
      "User" => Ok(AccessPolicyPermissionLevel::User),
      "Editor" => Ok(AccessPolicyPermissionLevel::Editor),
      "Admin" => Ok(AccessPolicyPermissionLevel::Admin),
      _ => Err(format!("Invalid permission level: {}", string))
    }
    
  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "inheritance_level")]
pub enum AccessPolicyInheritanceLevel {
  Disabled,
  Enabled,
  Required
}

impl fmt::Display for AccessPolicyInheritanceLevel {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyInheritanceLevel::Disabled => write!(f, "Disabled"),
      AccessPolicyInheritanceLevel::Enabled => write!(f, "Enabled"),
      AccessPolicyInheritanceLevel::Required => write!(f, "Required")
    }
  }
}

impl FromStr for AccessPolicyInheritanceLevel {

  type Err = String;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Disabled" => Ok(AccessPolicyInheritanceLevel::Disabled),
      "Enabled" => Ok(AccessPolicyInheritanceLevel::Enabled),
      "Required" => Ok(AccessPolicyInheritanceLevel::Required),
      _ => Err(format!("Invalid inheritance level: {}", string))
    }

  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "scoped_resource_type")]
pub enum AccessPolicyScopedResourceType {
  Instance,
  Workspace,
  Project,
  Item,
  Action,
  User,
  Role,
  Group,
  App,
  AppCredential,
  Milestone,
}

impl fmt::Display for AccessPolicyScopedResourceType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyScopedResourceType::Workspace => write!(f, "Workspace"),
      AccessPolicyScopedResourceType::Project => write!(f, "Project"),
      AccessPolicyScopedResourceType::Milestone => write!(f, "Milestone"),
      AccessPolicyScopedResourceType::Item => write!(f, "Item"),
      AccessPolicyScopedResourceType::Action => write!(f, "Action"),
      AccessPolicyScopedResourceType::Role => write!(f, "Role"),
      AccessPolicyScopedResourceType::Group => write!(f, "Group"),
      AccessPolicyScopedResourceType::User => write!(f, "User"),
      AccessPolicyScopedResourceType::App => write!(f, "App"),
      AccessPolicyScopedResourceType::AppCredential => write!(f, "AppCredential"),
      AccessPolicyScopedResourceType::Instance => write!(f, "Instance")
    }
  }
}

impl FromStr for AccessPolicyScopedResourceType {

  type Err = String;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Workspace" => Ok(AccessPolicyScopedResourceType::Workspace),
      "Project" => Ok(AccessPolicyScopedResourceType::Project),
      "Milestone" => Ok(AccessPolicyScopedResourceType::Milestone),
      "Item" => Ok(AccessPolicyScopedResourceType::Item),
      "Action" => Ok(AccessPolicyScopedResourceType::Action),
      "Role" => Ok(AccessPolicyScopedResourceType::Role),
      "Group" => Ok(AccessPolicyScopedResourceType::Group),
      "User" => Ok(AccessPolicyScopedResourceType::User),
      "App" => Ok(AccessPolicyScopedResourceType::App),
      _ => Err(format!("Invalid scoped resource type: {}", string))
    }

  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "principal_type")]
pub enum AccessPolicyPrincipalType {

  /// A resource that identifies a user.
  User,

  /// A resource that identifies multiple users, apps, and other groups.
  Group,

  /// A resource that identifies a role.
  Role,

  /// A resource that identifies an app.
  App

}

impl fmt::Display for AccessPolicyPrincipalType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyPrincipalType::App => write!(f, "App"),
      AccessPolicyPrincipalType::Group => write!(f, "Group"),
      AccessPolicyPrincipalType::Role => write!(f, "Role"),
      AccessPolicyPrincipalType::User => write!(f, "User")
    }
  }
}

impl FromStr for AccessPolicyPrincipalType {

  type Err = String;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "App" => Ok(AccessPolicyPrincipalType::App),
      "Group" => Ok(AccessPolicyPrincipalType::Group),
      "Role" => Ok(AccessPolicyPrincipalType::Role),
      "User" => Ok(AccessPolicyPrincipalType::User),
      _ => Err(format!("Invalid principal type: {}", string))
    }

  }

}

/// A piece of information that defines the level of access and inheritance for a principal to perform an action.
pub struct AccessPolicy {

  /// The access policy's ID.
  pub id: Uuid,
  
  /// The action ID that this access policy refers to.
  pub action_id: Uuid,

  pub permission_level: AccessPolicyPermissionLevel,

  pub inheritance_level: AccessPolicyInheritanceLevel,

  pub principal_type: AccessPolicyPrincipalType,

  pub principal_user_id: Option<Uuid>,

  pub principal_group_id: Option<Uuid>,

  pub principal_role_id: Option<Uuid>,

  pub principal_app_id: Option<Uuid>,

  pub scoped_resource_type: AccessPolicyScopedResourceType,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

#[derive(Debug)]
pub struct InitialAccessPolicyProperties {

  pub action_id: Uuid,

  pub permission_level: AccessPolicyPermissionLevel,

  pub inheritance_level: AccessPolicyInheritanceLevel,

  pub principal_type: AccessPolicyPrincipalType,

  pub principal_user_id: Option<Uuid>,

  pub principal_group_id: Option<Uuid>,

  pub principal_role_id: Option<Uuid>,

  pub principal_app_id: Option<Uuid>,

  pub scoped_resource_type: AccessPolicyScopedResourceType,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

#[derive(Debug)]
pub enum AccessPolicyCreationError<'a> {
  ResourceAlreadyExistsError(ResourceAlreadyExistsError<'a>),
  String(String),
  PostgresError(postgres::Error)
}

impl<'a> From<ResourceAlreadyExistsError<'a>> for AccessPolicyCreationError<'a> {
  fn from(error: ResourceAlreadyExistsError<'a>) -> Self {
    AccessPolicyCreationError::ResourceAlreadyExistsError(error)
  }
}

impl<'a> From<String> for AccessPolicyCreationError<'a> {
  fn from(error: String) -> Self {
    AccessPolicyCreationError::String(error)
  }
}

impl AccessPolicy {
  
  /// Instantiates an access policy.
  pub fn new(properties: AccessPolicy) -> Self {

    let access_policy = AccessPolicy {
      id: properties.id,
      action_id: properties.action_id,
      permission_level: properties.permission_level,
      inheritance_level: properties.inheritance_level,
      principal_type: properties.principal_type,
      principal_user_id: properties.principal_user_id,
      principal_group_id: properties.principal_group_id,
      principal_role_id: properties.principal_role_id,
      principal_app_id: properties.principal_app_id,
      scoped_resource_type: properties.scoped_resource_type,
      scoped_action_id: properties.scoped_action_id,
      scoped_app_id: properties.scoped_app_id,
      scoped_group_id: properties.scoped_group_id,
      scoped_item_id: properties.scoped_item_id,
      scoped_milestone_id: properties.scoped_milestone_id,
      scoped_project_id: properties.scoped_project_id,
      scoped_role_id: properties.scoped_role_id,
      scoped_user_id: properties.scoped_user_id,
      scoped_workspace_id: properties.scoped_workspace_id
    };

    return access_policy;

  }

  /// Creates a new access policy.
  pub fn create<'a>(initial_properties: &'a InitialAccessPolicyProperties, postgres_client: &mut postgres::Client) -> Result<Self, AccessPolicyCreationError<'a>> {

    // Insert the access policy into the database.
    let query = include_str!("../queries/access-policies/insert-access-policy-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.principal_type,
      &initial_properties.principal_user_id,
      &initial_properties.principal_group_id,
      &initial_properties.principal_role_id,
      &initial_properties.principal_app_id,
      &initial_properties.scoped_resource_type,
      &initial_properties.scoped_action_id,
      &initial_properties.scoped_app_id,
      &initial_properties.scoped_group_id,
      &initial_properties.scoped_item_id,
      &initial_properties.scoped_milestone_id,
      &initial_properties.scoped_project_id,
      &initial_properties.scoped_role_id,
      &initial_properties.scoped_user_id,
      &initial_properties.scoped_workspace_id,
      &initial_properties.permission_level,
      &initial_properties.inheritance_level,
      &initial_properties.action_id
    ];
    let rows = postgres_client.query(query, parameters);

    // Return the access policy.
    match rows {

      Ok(rows) => {

        match rows.get(0) {

          Some(row) => {

            let access_policy = AccessPolicy {
              id: row.get("id"),
              action_id: row.get("action_id"),
              permission_level: row.get("permission_level"),
              inheritance_level: row.get("inheritance_level"),
              principal_type: row.get("principal_type"),
              principal_user_id: row.get("principal_user_id"),
              principal_group_id: row.get("principal_group_id"),
              principal_role_id: row.get("principal_role_id"),
              principal_app_id: row.get("principal_app_id"),
              scoped_resource_type: row.get("scoped_resource_type"),
              scoped_action_id: row.get("scoped_action_id"),
              scoped_app_id: row.get("scoped_app_id"),
              scoped_group_id: row.get("scoped_group_id"),
              scoped_item_id: row.get("scoped_item_id"),
              scoped_milestone_id: row.get("scoped_milestone_id"),
              scoped_project_id: row.get("scoped_project_id"),
              scoped_role_id: row.get("scoped_role_id"),
              scoped_user_id: row.get("scoped_user_id"),
              scoped_workspace_id: row.get("scoped_workspace_id")
            };

            return Ok(access_policy);

          },

          None => {
            panic!("Client did not return a row.");
          }

        }
        
      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => {

          let error_code = db_error.code();
          match error_code {

            &SqlState::UNIQUE_VIOLATION => {

              let resource_already_exists_error = ResourceAlreadyExistsError {
                resource_type: "Access Policy"
              };

              Err(AccessPolicyCreationError::ResourceAlreadyExistsError(resource_already_exists_error))

            },
            
            _ => {
              Err(AccessPolicyCreationError::PostgresError(error))
            }

          }

        },

        None => {

          Err(AccessPolicyCreationError::PostgresError(error))

        }

      }

    }

  }

  /// Initializes the access policies table.
  pub fn initialize_access_policies_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/access-policies/initialize-access-policies-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

  /// Deletes this access policy.
  pub fn delete(&self) {
    

  }

}

#[cfg(test)]
mod tests;