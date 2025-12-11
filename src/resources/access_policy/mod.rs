
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

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Copy, Serialize, Deserialize, Default, PartialOrd)]
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
  ScopedResourceIDMissingError(AccessPolicyResourceType),

  #[error("An ancestor resource of type {0} is required for this access policy.")]
  OrphanedResourceError(AccessPolicyResourceType),

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
#[postgres(name = "access_policy_resource_type")]
pub enum AccessPolicyResourceType {
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

impl fmt::Display for AccessPolicyResourceType {
  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyResourceType::Workspace => write!(formatter, "Workspace"),
      AccessPolicyResourceType::Project => write!(formatter, "Project"),
      AccessPolicyResourceType::Milestone => write!(formatter, "Milestone"),
      AccessPolicyResourceType::Item => write!(formatter, "Item"),
      AccessPolicyResourceType::Action => write!(formatter, "Action"),
      AccessPolicyResourceType::Role => write!(formatter, "Role"),
      AccessPolicyResourceType::Group => write!(formatter, "Group"),
      AccessPolicyResourceType::User => write!(formatter, "User"),
      AccessPolicyResourceType::App => write!(formatter, "App"),
      AccessPolicyResourceType::AppCredential => write!(formatter, "AppCredential"),
      AccessPolicyResourceType::Instance => write!(formatter, "Instance")
    }
  }
}

impl FromStr for AccessPolicyResourceType {

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Instance" => Ok(AccessPolicyResourceType::Instance),
      "Workspace" => Ok(AccessPolicyResourceType::Workspace),
      "Project" => Ok(AccessPolicyResourceType::Project),
      "Milestone" => Ok(AccessPolicyResourceType::Milestone),
      "Item" => Ok(AccessPolicyResourceType::Item),
      "Action" => Ok(AccessPolicyResourceType::Action),
      "Role" => Ok(AccessPolicyResourceType::Role),
      "Group" => Ok(AccessPolicyResourceType::Group),
      "User" => Ok(AccessPolicyResourceType::User),
      "App" => Ok(AccessPolicyResourceType::App),
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

#[derive(Debug, Clone)]
pub enum Principal {

  User(Uuid),

  Group(Uuid),

  Role(Uuid),

  App(Uuid)

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

  pub scoped_resource_type: AccessPolicyResourceType,

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

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EditableAccessPolicyProperties {

  permission_level: Option<AccessPolicyPermissionLevel>,

  inheritance_level: Option<AccessPolicyInheritanceLevel>,

}

pub type ResourceHierarchy = Vec<(AccessPolicyResourceType, Option<Uuid>)>;

#[derive(Debug, Clone)]
pub enum IndividualPrincipal {
  User(Uuid),
  App(Uuid)
}

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

  pub scoped_resource_type: AccessPolicyResourceType,

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
  pub async fn count(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, AccessPolicyError> {

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
    let where_clause = sanitized_filter.where_clause.and_then(|string| Some(string)).unwrap_or("".to_string());
    let where_clause = match individual_principal {
      
      Some(individual_principal) => {
        
        let additional_condition = match individual_principal {

          IndividualPrincipal::User(user_id) => format!("can_principal_get_access_policy('User', {}, NULL, access_policies.*)", quote_literal(&user_id.to_string())),
          IndividualPrincipal::App(app_id) => format!("can_principal_get_access_policy('App', NULL, {}, access_policies.*)", quote_literal(&app_id.to_string()))

        };

        if where_clause == "" { 
          
          additional_condition 
        
        } else { 
          
          format!("({}) AND {}", where_clause, additional_condition)
        
        }

      },

      None => where_clause

    };
    let where_clause = if where_clause == "" { where_clause } else { format!(" where {}", where_clause) };
    let query = format!("select count(*) from access_policies{}", where_clause);

    // Execute the query and return the count.
    let rows = postgres_client.query_one(&query, &[]).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new access policy.
  pub async fn create(initial_properties: &InitialAccessPolicyProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AccessPolicyError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/access_policies/insert-access-policy-row.sql");
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

    let query = include_str!("../../queries/access_policies/get-access-policy-row-by-id.sql");
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

    let table_query = include_str!("../../queries/access_policies/initialize_access_policies_table.sql");
    postgres_client.execute(table_query, &[]).await?;

    let get_prinicipal_access_policies_function = include_str!("../../queries/access_policies/create_function_get_principal_access_policies.sql");
    postgres_client.execute(get_prinicipal_access_policies_function, &[]).await?;

    let can_principal_get_access_policy_function = include_str!("../../queries/access_policies/create_function_can_principal_get_access_policy.sql");
    postgres_client.execute(can_principal_get_access_policy_function, &[]).await?;
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

                let scoped_resource_type = AccessPolicyResourceType::from_str(string_value)?;
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
  pub async fn list(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, AccessPolicyError> {
                            
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
    let where_clause = sanitized_filter.where_clause.and_then(|string| Some(string)).unwrap_or("".to_string());
    let where_clause = match individual_principal {
      
      Some(individual_principal) => {
        
        let additional_condition = match individual_principal {

          IndividualPrincipal::User(user_id) => format!("can_principal_get_access_policy('User', {}, NULL, access_policies.*)", quote_literal(&user_id.to_string())),
          IndividualPrincipal::App(app_id) => format!("can_principal_get_access_policy('App', NULL, {}, access_policies.*)", quote_literal(&app_id.to_string()))

        };

        if where_clause == "" { 
          
          additional_condition 
        
        } else { 
          
          format!("({}) AND {}", where_clause, additional_condition)
        
        }

      },

      None => where_clause

    };
    let where_clause = if where_clause == "" { where_clause } else { format!(" where {}", where_clause) };

    let limit_clause = sanitized_filter.limit.and_then(|limit| Some(format!(" limit {}", limit))).unwrap_or("".to_string());
    let offset_clause = sanitized_filter.offset.and_then(|offset| Some(format!(" offset {}", offset))).unwrap_or("".to_string());
    let query = format!("select * from access_policies{}{}{}", where_clause, limit_clause, offset_clause);

    // Execute the query.
    let parsed_parameters = Self::parse_slashstepql_parameters(&sanitized_filter.parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = postgres_client.query(&query, &parameters).await?;
    let access_policies = rows.iter().map(AccessPolicy::convert_from_row).collect();
    return Ok(access_policies);

  }

  /// Returns a list of access policies based on a hierarchy.
  pub async fn list_by_hierarchy(principal: &Principal, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, postgres_client: &mut deadpool_postgres::Client) -> Result<Vec<Self>, AccessPolicyError> {

    let mut query_clauses: Vec<String> = Vec::new();

    for (resource_type, resource_id) in resource_hierarchy {

      match resource_type {

        AccessPolicyResourceType::Instance => query_clauses.push(format!("scoped_resource_type = 'Instance'")),
        AccessPolicyResourceType::Workspace => query_clauses.push(format!("scoped_workspace_id = {}", resource_id.expect("A workspace ID must be provided."))),
        AccessPolicyResourceType::Project => query_clauses.push(format!("scoped_project_id = {}", resource_id.expect("A project ID must be provided."))),
        AccessPolicyResourceType::Milestone => query_clauses.push(format!("scoped_milestone_id = {}", resource_id.expect("A milestone ID must be provided."))),
        AccessPolicyResourceType::Item => query_clauses.push(format!("scoped_item_id = {}", resource_id.expect("An item ID must be provided."))),
        AccessPolicyResourceType::Action => query_clauses.push(format!("scoped_action_id = {}", resource_id.expect("An action ID must be provided."))),
        AccessPolicyResourceType::User => query_clauses.push(format!("scoped_user_id = {}", resource_id.expect("A user ID must be provided."))),
        AccessPolicyResourceType::Role => query_clauses.push(format!("scoped_role_id = {}", resource_id.expect("A role ID must be provided."))),
        AccessPolicyResourceType::Group => query_clauses.push(format!("scoped_group_id = {}", resource_id.expect("A group ID must be provided."))),
        AccessPolicyResourceType::App => query_clauses.push(format!("scoped_app_id = {}", resource_id.expect("An app ID must be provided."))),
        AccessPolicyResourceType::AppCredential => query_clauses.push(format!("scoped_app_credential_id = {}", resource_id.expect("An app credential ID must be provided.")))

      }

    }

    // This will turn the query into something like:
    // action_id = $1 and (scoped_resource_type = 'Instance' or scoped_workspace_id = $2 or scoped_project_id = $3 or scoped_milestone_id = $4 or scoped_item_id = $5)
    let principal_clause = match principal {

      Principal::User(user_id) => format!("principal_user_id = '{}'", user_id),
      Principal::Group(group_id) => format!("principal_group_id = '{}'", group_id),
      Principal::Role(role_id) => format!("principal_role_id = '{}'", role_id),
      Principal::App(app_id) => format!("principal_app_id = '{}'", app_id)

    };
    let mut query_filter = String::new();
    query_filter.push_str(format!("{} and action_id = {} and (", principal_clause, quote_literal(&action_id.to_string())).as_str());
    for i in 0..query_clauses.len() {

      if i > 0 {

        query_filter.push_str(" or ");

      }

      query_filter.push_str(&query_clauses[i]);

    }
    query_filter.push_str(")");
    
    let access_policies: Vec<AccessPolicy> = AccessPolicy::list(&query_filter, postgres_client, None).await?;

    return Ok(access_policies);

  }

  /* Instance methods */
  /// Deletes this access policy.
  pub async fn delete(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<(), AccessPolicyError> {

    let query = include_str!("../../queries/access_policies/delete-access-policy-row.sql");
    postgres_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: &Option<T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    if let Some(parameter_value) = parameter_value.clone() {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  /// Updates this access policy and returns a new instance of the access policy.
  pub async fn update(&self, properties: &EditableAccessPolicyProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AccessPolicyError> {

    let query = String::from("update access_policies set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

    postgres_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "permission_level", &properties.permission_level);
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "inheritance_level", &properties.inheritance_level);

    query.push_str(format!(" where id = ${} returning *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = postgres_client.query_one(&query, &parameters).await?;
    postgres_client.query("commit;", &[]).await?;

    let access_policy = AccessPolicy::convert_from_row(&row);
    return Ok(access_policy);

  }

  pub async fn get_hierarchy(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, AccessPolicyError> {

    let mut hierarchy: ResourceHierarchy = vec![];
    let mut selected_resource_type: AccessPolicyResourceType = self.scoped_resource_type.clone();
    let mut selected_resource_id: Option<Uuid> = match self.scoped_resource_type {

      AccessPolicyResourceType::Instance => None,

      AccessPolicyResourceType::Action => self.scoped_action_id,

      AccessPolicyResourceType::App => self.scoped_app_id,

      AccessPolicyResourceType::AppCredential => self.scoped_app_credential_id,

      AccessPolicyResourceType::Group => self.scoped_group_id,

      AccessPolicyResourceType::Item => self.scoped_item_id,

      AccessPolicyResourceType::Milestone => self.scoped_milestone_id,

      AccessPolicyResourceType::Project => self.scoped_project_id,

      AccessPolicyResourceType::Role => self.scoped_role_id,

      AccessPolicyResourceType::User => self.scoped_user_id,

      AccessPolicyResourceType::Workspace => self.scoped_workspace_id

    };
    
    loop {

      match selected_resource_type {

        // Instance
        AccessPolicyResourceType::Instance => break,

        // Action -> (App | Instance)
        AccessPolicyResourceType::Action => {

          let Some(action_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Action));

          };

          hierarchy.push((AccessPolicyResourceType::Action, Some(action_id)));

          let action = match Action::get_by_id(&action_id, postgres_client).await {

            Ok(action) => action,

            Err(error) => match error {

              ActionError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::Action)),

              _ => return Err(AccessPolicyError::ActionError(error))

            }

          };

          if let Some(app_id) = action.app_id {

            selected_resource_type = AccessPolicyResourceType::App;
            selected_resource_id = Some(app_id);

          } else {

            selected_resource_type = AccessPolicyResourceType::Instance;
            selected_resource_id = None;

          }
 
        }

        // Workspace -> Instance
        AccessPolicyResourceType::Workspace => {

          let Some(scoped_workspace_id) = self.scoped_workspace_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

          };

          hierarchy.push((AccessPolicyResourceType::Workspace, Some(scoped_workspace_id)));

        },

        // Project -> Workspace
        AccessPolicyResourceType::Project => {

          let Some(scoped_project_id) = self.scoped_project_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

          };

          hierarchy.push((AccessPolicyResourceType::Project, Some(scoped_project_id)));

          let project = match Project::get_by_id(&scoped_project_id, postgres_client).await {

            Ok(project) => project,
            
            Err(error) => match error {

              ProjectError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::Project)),

              _ => return Err(AccessPolicyError::ProjectError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::Workspace;
          selected_resource_id = Some(project.workspace_id);

        },

        // Item -> Project
        AccessPolicyResourceType::Item => {

          let Some(scoped_item_id) = self.scoped_item_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Item));

          };

          hierarchy.push((AccessPolicyResourceType::Item, Some(scoped_item_id)));

          let item = Item::get_by_id(&scoped_item_id, postgres_client).await?;

          selected_resource_type = AccessPolicyResourceType::Project;
          selected_resource_id = Some(item.project_id);

        },

        // User -> Instance
        AccessPolicyResourceType::User => {

          let Some(scoped_user_id) = self.scoped_user_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

          };

          hierarchy.push((AccessPolicyResourceType::User, Some(scoped_user_id)));

        },

        // Role -> (Project | Workspace | Group | Instance)
        AccessPolicyResourceType::Role => {

          let Some(scoped_role_id) = self.scoped_role_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Role));

          };

          hierarchy.push((AccessPolicyResourceType::Role, Some(scoped_role_id)));

          let role = match Role::get_by_id(&scoped_role_id, postgres_client).await {

            Ok(role) => role,

            Err(error) => match error {

              RoleError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::Role)),

              _ => return Err(AccessPolicyError::RoleError(error))

            }

          };

          match role.parent_resource_type {

            RoleParentResourceType::Instance => {

              selected_resource_type = AccessPolicyResourceType::Instance;
              selected_resource_id = None;

            },

            RoleParentResourceType::Workspace => {

              let Some(workspace_id) = role.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            },

            RoleParentResourceType::Project => {

              let Some(project_id) = role.parent_project_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

              };

              selected_resource_type = AccessPolicyResourceType::Project;
              selected_resource_id = Some(project_id);

            },

            RoleParentResourceType::Group => {

              let Some(group_id) = role.parent_group_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

              };

              selected_resource_type = AccessPolicyResourceType::Group;
              selected_resource_id = Some(group_id);

            }

          }

        },

        // Group -> Instance
        AccessPolicyResourceType::Group => {

          let Some(group_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

          };

          hierarchy.push((AccessPolicyResourceType::Group, Some(group_id)));

          selected_resource_type = AccessPolicyResourceType::Instance;
          selected_resource_id = None;

        }

        // App -> (Workspace | User | Instance)
        AccessPolicyResourceType::App => {

          let Some(app_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::App));

          };

          hierarchy.push((AccessPolicyResourceType::App, Some(app_id)));

          let app = match App::get_by_id(&app_id, postgres_client).await {

            Ok(app) => app,

            Err(error) => match error {

              AppError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::App)),

              _ => return Err(AccessPolicyError::AppError(error))

            }

          };

          match app.parent_resource_type {

            AppParentResourceType::Instance => {

              selected_resource_type = AccessPolicyResourceType::Instance;
              selected_resource_id = None;

            },

            AppParentResourceType::Workspace => {

              let Some(workspace_id) = app.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            },

            AppParentResourceType::User => {

              let Some(user_id) = app.parent_user_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

              };

              selected_resource_type = AccessPolicyResourceType::User;
              selected_resource_id = Some(user_id);

            }

          }

        }

        // AppCredential -> App
        AccessPolicyResourceType::AppCredential => {

          let Some(app_credential_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppCredential));

          };

          hierarchy.push((AccessPolicyResourceType::AppCredential, Some(app_credential_id)));

          let app_credential = match AppCredential::get_by_id(&app_credential_id, postgres_client).await {

            Ok(app_credential) => app_credential,

            Err(error) => match error {

              AppCredentialError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::AppCredential)),

              _ => return Err(AccessPolicyError::AppCredentialError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::App;
          selected_resource_id = Some(app_credential.app_id);

        }

        // Milestone -> (Project | Workspace)
        AccessPolicyResourceType::Milestone => {

          let Some(milestone_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Milestone));

          };

          hierarchy.push((AccessPolicyResourceType::Milestone, Some(milestone_id)));

          let milestone = match Milestone::get_by_id(&milestone_id, postgres_client).await {

            Ok(milestone) => milestone,

            Err(error) => match error {

              MilestoneError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::Milestone)),

              _ => return Err(AccessPolicyError::MilestoneError(error))

            }

          };

          match milestone.parent_resource_type {

            MilestoneParentResourceType::Project => {

              let Some(project_id) = milestone.parent_project_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

              };

              selected_resource_type = AccessPolicyResourceType::Project;
              selected_resource_id = Some(project_id);

            },

            MilestoneParentResourceType::Workspace => {

              let Some(workspace_id) = milestone.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            }

          }

        }

      }
      
    }

    hierarchy.push((AccessPolicyResourceType::Instance, None));

    return Ok(hierarchy);

  }

}

/// To reduce line count, tests are in a separate module.
#[cfg(test)]
mod tests;