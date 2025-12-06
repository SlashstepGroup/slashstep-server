
/**
 * 
 * This module defines the implementation and types of an access policy.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use core::{fmt};
use std::str::FromStr;
use pg_escape::quote_literal;
use postgres::{
  error::SqlState, 
  types::ToSql
};
use postgres_types::FromSql;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use crate::{
  resources::{action::{Action, ActionError}, app::{App, AppError, AppParentResourceType}, app_credential::{AppCredential, AppCredentialError}, item::{Item, ItemError}, milestone::{Milestone, MilestoneError, MilestoneParentResourceType}, project::{Project, ProjectError}, role::{Role, RoleError, RoleParentResourceType}}, utilities::slashstepql::{
    SlashstepQLError, 
    SlashstepQLFilterSanitizer, 
    SlashstepQLParameterType, 
    SlashstepQLSanitizeFunctionOptions
  }
};

pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id", 
  "principal_type", 
  "principal_user_id", 
  "principal_group_id", 
  "principal_role_id", 
  "principal_app_id",
  "scoped_resource_type", 
  "scoped_action_id", 
  "scoped_app_id",
  "scoped_app_credential_id",
  "scoped_group_id", 
  "scoped_item_id", 
  "scoped_milestone_id", 
  "scoped_project_id", 
  "scoped_role_id", 
  "scoped_user_id", 
  "scoped_workspace_id"
];

pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "principal_user_id", 
  "principal_group_id", 
  "principal_role_id", 
  "principal_app_id",
  "scoped_action_id", 
  "scoped_app_id", 
  "scoped_group_id",
  "scoped_app_credential_id",
  "scoped_item_id", 
  "scoped_milestone_id", 
  "scoped_project_id", 
  "scoped_role_id", 
  "scoped_user_id", 
  "scoped_workspace_id"
];

pub const DEFAULT_ACCESS_POLICY_LIST_LIMIT: i64 = 1000;

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Copy, Serialize, Deserialize, Default)]
#[postgres(name = "permission_level")]
pub enum AccessPolicyPermissionLevel {
  #[default]
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

#[derive(Debug, Error)]
pub enum AccessPolicyError {
  #[error("Invalid permission level: {0}")]
  InvalidPermissionLevel(String),

  #[error("Invalid inheritance level: {0}")]
  InvalidInheritanceLevel(String),

  #[error("Invalid scoped resource type: {0}")]
  InvalidScopedResourceType(String),

  #[error("Invalid principal type: {0}")]
  InvalidPrincipalType(String),

  #[error("A scoped resource ID is required for the {0} resource type.")]
  ScopedResourceIDMissingError(AccessPolicyScopedResourceType),

  #[error("An ancestor resource of type {0} is required for this access policy.")]
  OrphanedResourceError(AccessPolicyScopedResourceType),

  #[error("An access policy for action {0} already exists.")]
  ConflictError(Uuid),

  #[error(transparent)]
  UUIDError(#[from] uuid::Error),

  #[error("Couldn't find an access policy with ID \"{0}\".")]
  NotFoundError(Uuid),

  #[error(transparent)]
  SlashstepQLError(#[from] SlashstepQLError),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  ProjectError(#[from] ProjectError),

  #[error(transparent)]
  ItemError(#[from] ItemError),

  #[error(transparent)]
  ActionError(#[from] ActionError),

  #[error(transparent)]
  AppError(#[from] AppError),

  #[error(transparent)]
  AppCredentialError(#[from] AppCredentialError),

  #[error(transparent)]
  RoleError(#[from] RoleError),

  #[error(transparent)]
  MilestoneError(#[from] MilestoneError)
}

impl FromStr for AccessPolicyPermissionLevel {

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "None" => Ok(AccessPolicyPermissionLevel::None),
      "User" => Ok(AccessPolicyPermissionLevel::User),
      "Editor" => Ok(AccessPolicyPermissionLevel::Editor),
      "Admin" => Ok(AccessPolicyPermissionLevel::Admin),
      _ => Err(AccessPolicyError::InvalidPermissionLevel(string.to_string()))
    }
    
  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Copy, Serialize, Deserialize, Default)]
#[postgres(name = "inheritance_level")]
pub enum AccessPolicyInheritanceLevel {
  #[default]
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

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Disabled" => Ok(AccessPolicyInheritanceLevel::Disabled),
      "Enabled" => Ok(AccessPolicyInheritanceLevel::Enabled),
      "Required" => Ok(AccessPolicyInheritanceLevel::Required),
      _ => Err(AccessPolicyError::InvalidInheritanceLevel(string.to_string()))
    }

  }

}

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default)]
#[postgres(name = "scoped_resource_type")]
pub enum AccessPolicyScopedResourceType {
  #[default]
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
  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyScopedResourceType::Workspace => write!(formatter, "Workspace"),
      AccessPolicyScopedResourceType::Project => write!(formatter, "Project"),
      AccessPolicyScopedResourceType::Milestone => write!(formatter, "Milestone"),
      AccessPolicyScopedResourceType::Item => write!(formatter, "Item"),
      AccessPolicyScopedResourceType::Action => write!(formatter, "Action"),
      AccessPolicyScopedResourceType::Role => write!(formatter, "Role"),
      AccessPolicyScopedResourceType::Group => write!(formatter, "Group"),
      AccessPolicyScopedResourceType::User => write!(formatter, "User"),
      AccessPolicyScopedResourceType::App => write!(formatter, "App"),
      AccessPolicyScopedResourceType::AppCredential => write!(formatter, "AppCredential"),
      AccessPolicyScopedResourceType::Instance => write!(formatter, "Instance")
    }
  }
}

impl FromStr for AccessPolicyScopedResourceType {

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Instance" => Ok(AccessPolicyScopedResourceType::Instance),
      "Workspace" => Ok(AccessPolicyScopedResourceType::Workspace),
      "Project" => Ok(AccessPolicyScopedResourceType::Project),
      "Milestone" => Ok(AccessPolicyScopedResourceType::Milestone),
      "Item" => Ok(AccessPolicyScopedResourceType::Item),
      "Action" => Ok(AccessPolicyScopedResourceType::Action),
      "Role" => Ok(AccessPolicyScopedResourceType::Role),
      "Group" => Ok(AccessPolicyScopedResourceType::Group),
      "User" => Ok(AccessPolicyScopedResourceType::User),
      "App" => Ok(AccessPolicyScopedResourceType::App),
      _ => Err(AccessPolicyError::InvalidScopedResourceType(string.to_string()))
    }

  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default)]
#[postgres(name = "principal_type")]
pub enum AccessPolicyPrincipalType {

  /// A resource that identifies a user.
  #[default]
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

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "App" => Ok(AccessPolicyPrincipalType::App),
      "Group" => Ok(AccessPolicyPrincipalType::Group),
      "Role" => Ok(AccessPolicyPrincipalType::Role),
      "User" => Ok(AccessPolicyPrincipalType::User),
      _ => Err(AccessPolicyError::InvalidPrincipalType(string.to_string()))
    }

  }

}

#[derive(Debug, Default)]
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

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

pub struct EditableAccessPolicyProperties {

  permission_level: Option<AccessPolicyPermissionLevel>,

  inheritance_level: Option<AccessPolicyInheritanceLevel>,

}

pub type ResourceHierarchy = Vec<(AccessPolicyScopedResourceType, Option<Uuid>)>;

/// A piece of information that defines the level of access and inheritance for a principal to perform an action.
#[derive(Debug, Serialize, Deserialize)]
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

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

impl AccessPolicy {

  /* Static methods */
  /// Counts the number of access policies based on a query.
  pub async fn count(query: &str, postgres_client: &mut deadpool_postgres::Client) -> Result<i64, AccessPolicyError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: None,
      maximum_limit: None,
      should_ignore_limit: true,
      should_ignore_offset: true
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let where_clause = sanitized_filter.where_clause.and_then(|string| Some(format!(" where {}", string))).unwrap_or("".to_string());
    let query = format!("select count(*) from hydrated_access_policies{}", where_clause);

    // Execute the query and return the count.
    let rows = postgres_client.query_one(&query, &[]).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new access policy.
  pub async fn create(initial_properties: &InitialAccessPolicyProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AccessPolicyError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/access-policies/insert-access-policy-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.principal_type,
      &initial_properties.principal_user_id,
      &initial_properties.principal_group_id,
      &initial_properties.principal_role_id,
      &initial_properties.principal_app_id,
      &initial_properties.scoped_resource_type,
      &initial_properties.scoped_action_id,
      &initial_properties.scoped_app_id,
      &initial_properties.scoped_app_credential_id,
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
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => {

        match db_error.code() {

          &SqlState::UNIQUE_VIOLATION => AccessPolicyError::ConflictError(initial_properties.action_id),
          
          _ => AccessPolicyError::PostgresError(error)

        }

      },

      None => AccessPolicyError::PostgresError(error)
    
    })?;

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
      scoped_app_credential_id: row.get("scoped_app_credential_id"),
      scoped_group_id: row.get("scoped_group_id"),
      scoped_item_id: row.get("scoped_item_id"),
      scoped_milestone_id: row.get("scoped_milestone_id"),
      scoped_project_id: row.get("scoped_project_id"),
      scoped_role_id: row.get("scoped_role_id"),
      scoped_user_id: row.get("scoped_user_id"),
      scoped_workspace_id: row.get("scoped_workspace_id")
    };

    return Ok(access_policy);

  }

  /// Gets an access policy by its ID.
  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AccessPolicyError> {

    let query = include_str!("../../queries/access-policies/get-access-policy-row-by-id.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[&id];
    let row = match postgres_client.query_opt(query, parameters).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(AccessPolicyError::NotFoundError(id.clone()))

      },

      Err(error) => return Err(AccessPolicyError::PostgresError(error))

    };

    let access_policy = AccessPolicy::convert_from_row(&row);

    return Ok(access_policy);

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AccessPolicy {
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
      scoped_app_credential_id: row.get("scoped_app_credential_id"),
      scoped_group_id: row.get("scoped_group_id"),
      scoped_item_id: row.get("scoped_item_id"),
      scoped_milestone_id: row.get("scoped_milestone_id"),
      scoped_project_id: row.get("scoped_project_id"),
      scoped_role_id: row.get("scoped_role_id"),
      scoped_user_id: row.get("scoped_user_id"),
      scoped_workspace_id: row.get("scoped_workspace_id")
    };

  }

  /// Initializes the access policies table.
  pub async fn initialize_access_policies_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AccessPolicyError> {

    let table_query = include_str!("../../queries/access-policies/initialize-access-policies-table.sql");
    postgres_client.execute(table_query, &[]).await?;

    let view_query = include_str!("../../queries/access-policies/initialize-hydrated-access-policies-view.sql");
    postgres_client.execute(view_query, &[]).await?;
    return Ok(());

  }

  fn parse_slashstepql_parameters(slashstepql_parameters: &Vec<(String, SlashstepQLParameterType)>) -> Result<Vec<Box<dyn ToSql + Sync + Send + '_>>, AccessPolicyError> {

    let mut parameters: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

    for (key, value) in slashstepql_parameters {

      match value {

        SlashstepQLParameterType::String(string_value) => {

          if UUID_QUERY_KEYS.contains(&key.as_str()) {

            let uuid = Uuid::parse_str(string_value)?;
            parameters.push(Box::new(uuid));

          } else {

            match key.as_str() {

              "scoped_resource_type" => {

                let scoped_resource_type = AccessPolicyScopedResourceType::from_str(string_value)?;
                parameters.push(Box::new(scoped_resource_type));

              },
              
              "principal_type" => {

                let principal_type = AccessPolicyPrincipalType::from_str(string_value)?;
                parameters.push(Box::new(principal_type));

              },

              "inheritance_level" => {

                let inheritance_level = AccessPolicyInheritanceLevel::from_str(string_value)?;
                parameters.push(Box::new(inheritance_level));

              },

              "permission_level" => {

                let permission_level = AccessPolicyPermissionLevel::from_str(string_value)?;
                parameters.push(Box::new(permission_level));

              },

              _ => {

                parameters.push(Box::new(string_value));

              }

            }

          }
          
        },

        SlashstepQLParameterType::Number(number_value) => {

          parameters.push(Box::new(number_value));

        },

        SlashstepQLParameterType::Boolean(boolean_value) => {

          parameters.push(Box::new(boolean_value));

        }

      }

    }

    return Ok(parameters);

  }

  /// Returns a list of access policies based on a query.
  pub async fn list(query: &str, postgres_client: &mut deadpool_postgres::Client) -> Result<Vec<Self>, AccessPolicyError> {
                            
    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ACCESS_POLICY_LIST_LIMIT),
      maximum_limit: None,
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let where_clause = sanitized_filter.where_clause.and_then(|string| Some(format!(" where {}", string))).unwrap_or("".to_string());
    let limit_clause = sanitized_filter.limit.and_then(|limit| Some(format!(" limit {}", limit))).unwrap_or("".to_string());
    let offset_clause = sanitized_filter.offset.and_then(|offset| Some(format!(" offset {}", offset))).unwrap_or("".to_string());
    let query = format!("select * from hydrated_access_policies{}{}{}", where_clause, limit_clause, offset_clause);

    // Execute the query.
    let parsed_parameters = Self::parse_slashstepql_parameters(&sanitized_filter.parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = postgres_client.query(&query, &parameters).await?;
    let access_policies = rows.iter().map(AccessPolicy::convert_from_row).collect();
    return Ok(access_policies);

  }

  /// Returns a list of access policies based on a hierarchy.
  pub async fn list_by_hierarchy(resource_hierarchy: &ResourceHierarchy, action_id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Vec<Self>, AccessPolicyError> {

    let mut query_clauses: Vec<String> = Vec::new();

    for (resource_type, resource_id) in resource_hierarchy {

      match resource_type {

        AccessPolicyScopedResourceType::Instance => query_clauses.push(format!("scoped_resource_type = 'Instance'")),
        AccessPolicyScopedResourceType::Workspace => query_clauses.push(format!("scoped_workspace_id = {}", resource_id.expect("A workspace ID must be provided."))),
        AccessPolicyScopedResourceType::Project => query_clauses.push(format!("scoped_project_id = {}", resource_id.expect("A project ID must be provided."))),
        AccessPolicyScopedResourceType::Milestone => query_clauses.push(format!("scoped_milestone_id = {}", resource_id.expect("A milestone ID must be provided."))),
        AccessPolicyScopedResourceType::Item => query_clauses.push(format!("scoped_item_id = {}", resource_id.expect("An item ID must be provided."))),
        AccessPolicyScopedResourceType::Action => query_clauses.push(format!("scoped_action_id = {}", resource_id.expect("An action ID must be provided."))),
        AccessPolicyScopedResourceType::User => query_clauses.push(format!("scoped_user_id = {}", resource_id.expect("A user ID must be provided."))),
        AccessPolicyScopedResourceType::Role => query_clauses.push(format!("scoped_role_id = {}", resource_id.expect("A role ID must be provided."))),
        AccessPolicyScopedResourceType::Group => query_clauses.push(format!("scoped_group_id = {}", resource_id.expect("A group ID must be provided."))),
        AccessPolicyScopedResourceType::App => query_clauses.push(format!("scoped_app_id = {}", resource_id.expect("An app ID must be provided."))),
        AccessPolicyScopedResourceType::AppCredential => query_clauses.push(format!("scoped_app_credential_id = {}", resource_id.expect("An app credential ID must be provided.")))

      }

    }

    // This will turn the query into something like:
    // action_id = $1 and (scoped_resource_type = 'Instance' or scoped_workspace_id = $2 or scoped_project_id = $3 or scoped_milestone_id = $4 or scoped_item_id = $5)
    let mut query_filter = String::new();
    query_filter.push_str(format!("action_id = {} and (", quote_literal(&action_id.to_string())).as_str());
    for i in 0..query_clauses.len() {

      if i > 0 {

        query_filter.push_str(" or ");

      }

      query_filter.push_str(&query_clauses[i]);

    }
    query_filter.push_str(")");
    
    let access_policies: Vec<AccessPolicy> = AccessPolicy::list(&query_filter, postgres_client).await?;

    return Ok(access_policies);

  }

  /* Instance methods */
  /// Deletes this access policy.
  pub async fn delete(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<(), AccessPolicyError> {

    let query = include_str!("../../queries/access-policies/delete-access-policy-row.sql");
    postgres_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  fn add_parameter<T: ToSql + Sync + Clone + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync>>, mut query: String, key: &str, parameter_value: &Option<T>) -> (Vec<Box<dyn ToSql + Sync>>, String) {

    if let Some(parameter_value) = parameter_value.clone() {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  /// Updates this access policy and returns a new instance of the access policy.
  pub async fn update(&self, properties: &EditableAccessPolicyProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AccessPolicyError> {

    let query = String::from("update access_policies set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync>> = Vec::new();

    postgres_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "permission_level", &properties.permission_level);
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "inheritance_level", &properties.inheritance_level);

    query.push_str(format!(" where id = ${} returning *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters = parameter_boxes.iter().map(|parameter| parameter.as_ref()).collect::<Vec<&(dyn ToSql + Sync)>>();
    let row = postgres_client.query_one(&query, &parameters).await?;
    postgres_client.query("commit;", &[]).await?;

    let access_policy = AccessPolicy::convert_from_row(&row);
    return Ok(access_policy);

  }

  pub async fn get_hierarchy(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, AccessPolicyError> {

    let mut hierarchy: ResourceHierarchy = vec![];
    let mut selected_resource_type: AccessPolicyScopedResourceType = self.scoped_resource_type.clone();
    let mut selected_resource_id: Option<Uuid> = match self.scoped_resource_type {

      AccessPolicyScopedResourceType::Instance => None,

      AccessPolicyScopedResourceType::Action => self.scoped_action_id,

      AccessPolicyScopedResourceType::App => self.scoped_app_id,

      AccessPolicyScopedResourceType::AppCredential => self.scoped_app_credential_id,

      AccessPolicyScopedResourceType::Group => self.scoped_group_id,

      AccessPolicyScopedResourceType::Item => self.scoped_item_id,

      AccessPolicyScopedResourceType::Milestone => self.scoped_milestone_id,

      AccessPolicyScopedResourceType::Project => self.scoped_project_id,

      AccessPolicyScopedResourceType::Role => self.scoped_role_id,

      AccessPolicyScopedResourceType::User => self.scoped_user_id,

      AccessPolicyScopedResourceType::Workspace => self.scoped_workspace_id

    };
    
    loop {

      match selected_resource_type {

        // Instance
        AccessPolicyScopedResourceType::Instance => break,

        // Action -> (App | Instance)
        AccessPolicyScopedResourceType::Action => {

          let Some(action_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Action));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Action, Some(action_id)));

          let action = match Action::get_by_id(&action_id, postgres_client).await {

            Ok(action) => action,

            Err(error) => match error {

              ActionError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::Action)),

              _ => return Err(AccessPolicyError::ActionError(error))

            }

          };

          if let Some(app_id) = action.app_id {

            selected_resource_type = AccessPolicyScopedResourceType::App;
            selected_resource_id = Some(app_id);

          } else {

            selected_resource_type = AccessPolicyScopedResourceType::Instance;
            selected_resource_id = None;

          }
 
        }

        // Workspace -> Instance
        AccessPolicyScopedResourceType::Workspace => {

          let Some(scoped_workspace_id) = self.scoped_workspace_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Workspace));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Workspace, Some(scoped_workspace_id)));

        },

        // Project -> Workspace
        AccessPolicyScopedResourceType::Project => {

          let Some(scoped_project_id) = self.scoped_project_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Project));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Project, Some(scoped_project_id)));

          let project = match Project::get_by_id(&scoped_project_id, postgres_client).await {

            Ok(project) => project,
            
            Err(error) => match error {

              ProjectError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::Project)),

              _ => return Err(AccessPolicyError::ProjectError(error))

            }

          };

          selected_resource_type = AccessPolicyScopedResourceType::Workspace;
          selected_resource_id = Some(project.workspace_id);

        },

        // Item -> Project
        AccessPolicyScopedResourceType::Item => {

          let Some(scoped_item_id) = self.scoped_item_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Item));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Item, Some(scoped_item_id)));

          let item = Item::get_by_id(&scoped_item_id, postgres_client).await?;

          selected_resource_type = AccessPolicyScopedResourceType::Project;
          selected_resource_id = Some(item.project_id);

        },

        // User -> Instance
        AccessPolicyScopedResourceType::User => {

          let Some(scoped_user_id) = self.scoped_user_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::User));

          };

          hierarchy.push((AccessPolicyScopedResourceType::User, Some(scoped_user_id)));

        },

        // Role -> (Project | Workspace | Group | Instance)
        AccessPolicyScopedResourceType::Role => {

          let Some(scoped_role_id) = self.scoped_role_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Role));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Role, Some(scoped_role_id)));

          let role = match Role::get_by_id(&scoped_role_id, postgres_client).await {

            Ok(role) => role,

            Err(error) => match error {

              RoleError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::Role)),

              _ => return Err(AccessPolicyError::RoleError(error))

            }

          };

          match role.parent_resource_type {

            RoleParentResourceType::Instance => {

              selected_resource_type = AccessPolicyScopedResourceType::Instance;
              selected_resource_id = None;

            },

            RoleParentResourceType::Workspace => {

              let Some(workspace_id) = role.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            },

            RoleParentResourceType::Project => {

              let Some(project_id) = role.parent_project_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Project));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Project;
              selected_resource_id = Some(project_id);

            },

            RoleParentResourceType::Group => {

              let Some(group_id) = role.parent_group_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Group));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Group;
              selected_resource_id = Some(group_id);

            }

          }

        },

        // Group -> Instance
        AccessPolicyScopedResourceType::Group => {

          let Some(group_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Group));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Group, Some(group_id)));

          selected_resource_type = AccessPolicyScopedResourceType::Instance;
          selected_resource_id = None;

        }

        // App -> (Workspace | User | Instance)
        AccessPolicyScopedResourceType::App => {

          let Some(app_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::App));

          };

          hierarchy.push((AccessPolicyScopedResourceType::App, Some(app_id)));

          let app = match App::get_by_id(&app_id, postgres_client).await {

            Ok(app) => app,

            Err(error) => match error {

              AppError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::App)),

              _ => return Err(AccessPolicyError::AppError(error))

            }

          };

          match app.parent_resource_type {

            AppParentResourceType::Instance => {

              selected_resource_type = AccessPolicyScopedResourceType::Instance;
              selected_resource_id = None;

            },

            AppParentResourceType::Workspace => {

              let Some(workspace_id) = app.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            },

            AppParentResourceType::User => {

              let Some(user_id) = app.parent_user_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::User));

              };

              selected_resource_type = AccessPolicyScopedResourceType::User;
              selected_resource_id = Some(user_id);

            }

          }

        }

        // AppCredential -> App
        AccessPolicyScopedResourceType::AppCredential => {

          let Some(app_credential_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::AppCredential));

          };

          hierarchy.push((AccessPolicyScopedResourceType::AppCredential, Some(app_credential_id)));

          let app_credential = match AppCredential::get_by_id(&app_credential_id, postgres_client).await {

            Ok(app_credential) => app_credential,

            Err(error) => match error {

              AppCredentialError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::AppCredential)),

              _ => return Err(AccessPolicyError::AppCredentialError(error))

            }

          };

          selected_resource_type = AccessPolicyScopedResourceType::App;
          selected_resource_id = Some(app_credential.app_id);

        }

        // Milestone -> (Project | Workspace)
        AccessPolicyScopedResourceType::Milestone => {

          let Some(milestone_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Milestone));

          };

          hierarchy.push((AccessPolicyScopedResourceType::Milestone, Some(milestone_id)));

          let milestone = match Milestone::get_by_id(&milestone_id, postgres_client).await {

            Ok(milestone) => milestone,

            Err(error) => match error {

              MilestoneError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyScopedResourceType::Milestone)),

              _ => return Err(AccessPolicyError::MilestoneError(error))

            }

          };

          match milestone.parent_resource_type {

            MilestoneParentResourceType::Project => {

              let Some(project_id) = milestone.parent_project_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Project));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Project;
              selected_resource_id = Some(project_id);

            },

            MilestoneParentResourceType::Workspace => {

              let Some(workspace_id) = milestone.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyScopedResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyScopedResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            }

          }

        }

      }
      
    }

    hierarchy.push((AccessPolicyScopedResourceType::Instance, None));

    return Ok(hierarchy);

  }

}

/// To reduce line count, tests are in a separate module.
#[cfg(test)]
mod tests;