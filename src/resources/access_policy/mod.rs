
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
  resources::{action::{Action, ActionError}, action_log_entry::{ActionLogEntry, ActionLogEntryError}, app::{App, AppError, AppParentResourceType}, app_authorization::{AppAuthorization, AppAuthorizationError, AppAuthorizationParentResourceType}, app_authorization_credential::{AppAuthorizationCredential, AppAuthorizationCredentialError}, app_credential::{AppCredential, AppCredentialError}, group_membership::{GroupMembership, GroupMembershipError}, item::{Item, ItemError}, milestone::{Milestone, MilestoneError, MilestoneParentResourceType}, project::{Project, ProjectError}, role::{Role, RoleError, RoleParentResourceType}, role_memberships::{RoleMembership, RoleMembershipError}, session::{Session, SessionError}}, utilities::slashstepql::{
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
pub const DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT: i64 = 1000;

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
  ActionLogEntryError(#[from] ActionLogEntryError),

  #[error(transparent)]
  AppError(#[from] AppError),

  #[error(transparent)]
  AppCredentialError(#[from] AppCredentialError),

  #[error(transparent)]
  RoleError(#[from] RoleError),

  #[error(transparent)]
  RoleMembershipError(#[from] RoleMembershipError),

  #[error(transparent)]
  SessionError(#[from] SessionError),

  #[error(transparent)]
  MilestoneError(#[from] MilestoneError),

  #[error(transparent)]
  AppAuthorizationError(#[from] AppAuthorizationError),

  #[error(transparent)]
  AppAuthorizationCredentialError(#[from] AppAuthorizationCredentialError),

  #[error(transparent)]
  GroupMembershipError(#[from] GroupMembershipError),
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

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default)]
#[postgres(name = "access_policy_resource_type")]
pub enum AccessPolicyResourceType {
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Group,
  GroupMembership,
  HTTPTransaction,
  #[default]
  Instance,
  Item,
  Project,
  Role,
  RoleMembership,
  ServerLogEntry,
  Session,
  User,
  Milestone,
  Workspace
}

impl fmt::Display for AccessPolicyResourceType {
  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    match self {
      AccessPolicyResourceType::Action => write!(formatter, "Action"),
      AccessPolicyResourceType::ActionLogEntry => write!(formatter, "ActionLogEntry"),
      AccessPolicyResourceType::App => write!(formatter, "App"),
      AccessPolicyResourceType::AppAuthorization => write!(formatter, "AppAuthorization"),
      AccessPolicyResourceType::AppAuthorizationCredential => write!(formatter, "AppAuthorizationCredential"),
      AccessPolicyResourceType::AppCredential => write!(formatter, "AppCredential"),
      AccessPolicyResourceType::Group => write!(formatter, "Group"),
      AccessPolicyResourceType::GroupMembership => write!(formatter, "GroupMembership"),
      AccessPolicyResourceType::HTTPTransaction => write!(formatter, "HTTPTransaction"),
      AccessPolicyResourceType::Instance => write!(formatter, "Instance"),
      AccessPolicyResourceType::Item => write!(formatter, "Item"),
      AccessPolicyResourceType::Milestone => write!(formatter, "Milestone"),
      AccessPolicyResourceType::Project => write!(formatter, "Project"),
      AccessPolicyResourceType::Role => write!(formatter, "Role"),
      AccessPolicyResourceType::RoleMembership => write!(formatter, "RoleMembership"),
      AccessPolicyResourceType::ServerLogEntry => write!(formatter, "ServerLogEntry"),
      AccessPolicyResourceType::Session => write!(formatter, "Session"),
      AccessPolicyResourceType::User => write!(formatter, "User"),
      AccessPolicyResourceType::Workspace => write!(formatter, "Workspace")
    }
  }
}

impl FromStr for AccessPolicyResourceType {

  type Err = AccessPolicyError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Action" => Ok(AccessPolicyResourceType::Action),
      "ActionLogEntry" => Ok(AccessPolicyResourceType::ActionLogEntry),
      "App" => Ok(AccessPolicyResourceType::App),
      "AppAuthorization" => Ok(AccessPolicyResourceType::AppAuthorization),
      "AppAuthorizationCredential" => Ok(AccessPolicyResourceType::AppAuthorizationCredential),
      "AppCredential" => Ok(AccessPolicyResourceType::AppCredential),
      "Group" => Ok(AccessPolicyResourceType::Group),
      "GroupMembership" => Ok(AccessPolicyResourceType::GroupMembership),
      "HTTPTransaction" => Ok(AccessPolicyResourceType::HTTPTransaction),
      "Instance" => Ok(AccessPolicyResourceType::Instance),
      "Item" => Ok(AccessPolicyResourceType::Item),
      "Milestone" => Ok(AccessPolicyResourceType::Milestone),
      "Project" => Ok(AccessPolicyResourceType::Project),
      "Role" => Ok(AccessPolicyResourceType::Role),
      "RoleMembership" => Ok(AccessPolicyResourceType::RoleMembership),
      "ServerLogEntry" => Ok(AccessPolicyResourceType::ServerLogEntry),
      "Session" => Ok(AccessPolicyResourceType::Session),
      "User" => Ok(AccessPolicyResourceType::User),
      "Workspace" => Ok(AccessPolicyResourceType::Workspace),
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

  pub is_inheritance_enabled: bool,

  pub principal_type: AccessPolicyPrincipalType,

  pub principal_user_id: Option<Uuid>,

  pub principal_group_id: Option<Uuid>,

  pub principal_role_id: Option<Uuid>,

  pub principal_app_id: Option<Uuid>,

  pub scoped_resource_type: AccessPolicyResourceType,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_action_log_entry_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_app_authorization_id: Option<Uuid>,

  pub scoped_app_authorization_credential_id: Option<Uuid>,

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_group_membership_id: Option<Uuid>,

  pub scoped_http_transaction_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_role_membership_id: Option<Uuid>,

  pub scoped_server_log_entry_id: Option<Uuid>,

  pub scoped_session_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EditableAccessPolicyProperties {

  permission_level: Option<AccessPolicyPermissionLevel>,

  is_inheritance_enabled: Option<bool>,

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

  pub is_inheritance_enabled: bool,

  pub principal_type: AccessPolicyPrincipalType,

  pub principal_user_id: Option<Uuid>,

  pub principal_group_id: Option<Uuid>,

  pub principal_role_id: Option<Uuid>,

  pub principal_app_id: Option<Uuid>,

  pub scoped_resource_type: AccessPolicyResourceType,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_action_log_entry_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_app_authorization_id: Option<Uuid>,

  pub scoped_app_authorization_credential_id: Option<Uuid>,

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_group_membership_id: Option<Uuid>,

  pub scoped_http_transaction_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_role_membership_id: Option<Uuid>,

  pub scoped_server_log_entry_id: Option<Uuid>,

  pub scoped_session_id: Option<Uuid>,

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
      &initial_properties.action_id,
      &initial_properties.permission_level,
      &initial_properties.is_inheritance_enabled,
      &initial_properties.principal_type,
      &initial_properties.principal_user_id,
      &initial_properties.principal_group_id,
      &initial_properties.principal_role_id,
      &initial_properties.principal_app_id,
      &initial_properties.scoped_resource_type,
      &initial_properties.scoped_action_id,
      &initial_properties.scoped_action_log_entry_id,
      &initial_properties.scoped_app_id,
      &initial_properties.scoped_app_authorization_id,
      &initial_properties.scoped_app_authorization_credential_id,
      &initial_properties.scoped_app_credential_id,
      &initial_properties.scoped_group_membership_id,
      &initial_properties.scoped_http_transaction_id,
      &initial_properties.scoped_item_id,
      &initial_properties.scoped_milestone_id,
      &initial_properties.scoped_project_id,
      &initial_properties.scoped_role_id,
      &initial_properties.scoped_role_membership_id,
      &initial_properties.scoped_server_log_entry_id,
      &initial_properties.scoped_session_id,
      &initial_properties.scoped_user_id,
      &initial_properties.scoped_workspace_id
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

    let access_policy = AccessPolicy::convert_from_row(&row);

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
      is_inheritance_enabled: row.get("is_inheritance_enabled"),
      principal_type: row.get("principal_type"),
      principal_user_id: row.get("principal_user_id"),
      principal_group_id: row.get("principal_group_id"),
      principal_role_id: row.get("principal_role_id"),
      principal_app_id: row.get("principal_app_id"),
      scoped_resource_type: row.get("scoped_resource_type"),
      scoped_action_id: row.get("scoped_action_id"),
      scoped_action_log_entry_id: row.get("scoped_action_log_entry_id"),
      scoped_app_id: row.get("scoped_app_id"),
      scoped_app_authorization_id: row.get("scoped_app_authorization_id"),
      scoped_app_authorization_credential_id: row.get("scoped_app_authorization_credential_id"),
      scoped_app_credential_id: row.get("scoped_app_credential_id"),
      scoped_group_id: row.get("scoped_group_id"),
      scoped_group_membership_id: row.get("scoped_group_membership_id"),
      scoped_http_transaction_id: row.get("scoped_http_transaction_id"),
      scoped_item_id: row.get("scoped_item_id"),
      scoped_milestone_id: row.get("scoped_milestone_id"),
      scoped_project_id: row.get("scoped_project_id"),
      scoped_role_id: row.get("scoped_role_id"),
      scoped_role_membership_id: row.get("scoped_role_membership_id"),
      scoped_server_log_entry_id: row.get("scoped_server_log_entry_id"),
      scoped_session_id: row.get("scoped_session_id"),
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
      default_limit: Some(DEFAULT_ACCESS_POLICY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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

        AccessPolicyResourceType::Action => query_clauses.push(format!("scoped_action_id = {}", resource_id.expect("An action ID must be provided."))),
        AccessPolicyResourceType::ActionLogEntry => query_clauses.push(format!("scoped_action_log_entry_id = {}", resource_id.expect("An action log entry ID must be provided."))),
        AccessPolicyResourceType::App => query_clauses.push(format!("scoped_app_id = {}", resource_id.expect("An app ID must be provided."))),
        AccessPolicyResourceType::AppAuthorization => query_clauses.push(format!("scoped_app_authorization_id = {}", resource_id.expect("An app authorization ID must be provided."))),
        AccessPolicyResourceType::AppAuthorizationCredential => query_clauses.push(format!("scoped_app_authorization_credential_id = {}", resource_id.expect("An app authorization credential ID must be provided."))),
        AccessPolicyResourceType::AppCredential => query_clauses.push(format!("scoped_app_credential_id = {}", resource_id.expect("An app credential ID must be provided."))),
        AccessPolicyResourceType::Group => query_clauses.push(format!("scoped_group_id = {}", resource_id.expect("A group ID must be provided."))),
        AccessPolicyResourceType::GroupMembership => query_clauses.push(format!("scoped_group_membership_id = {}", resource_id.expect("A group membership ID must be provided."))), 
        AccessPolicyResourceType::HTTPTransaction => query_clauses.push(format!("scoped_http_transaction_id = {}", resource_id.expect("An HTTP transaction ID must be provided."))),
        AccessPolicyResourceType::Instance => query_clauses.push(format!("scoped_resource_type = 'Instance'")),
        AccessPolicyResourceType::Item => query_clauses.push(format!("scoped_item_id = {}", resource_id.expect("An item ID must be provided."))),
        AccessPolicyResourceType::Milestone => query_clauses.push(format!("scoped_milestone_id = {}", resource_id.expect("A milestone ID must be provided."))),
        AccessPolicyResourceType::Project => query_clauses.push(format!("scoped_project_id = {}", resource_id.expect("A project ID must be provided."))),
        AccessPolicyResourceType::Role => query_clauses.push(format!("scoped_role_id = {}", resource_id.expect("A role ID must be provided."))),
        AccessPolicyResourceType::RoleMembership => query_clauses.push(format!("scoped_role_membership_id = {}", resource_id.expect("A role membership ID must be provided."))),
        AccessPolicyResourceType::ServerLogEntry => query_clauses.push(format!("scoped_server_log_entry_id = {}", resource_id.expect("A server log entry ID must be provided."))),
        AccessPolicyResourceType::Session => query_clauses.push(format!("scoped_session_id = {}", resource_id.expect("A session ID must be provided."))),
        AccessPolicyResourceType::User => query_clauses.push(format!("scoped_user_id = {}", resource_id.expect("A user ID must be provided."))),
        AccessPolicyResourceType::Workspace => query_clauses.push(format!("scoped_workspace_id = {}", resource_id.expect("A workspace ID must be provided.")))

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
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "is_inheritance_enabled", &properties.is_inheritance_enabled);

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

      AccessPolicyResourceType::Action => self.scoped_action_id,
      AccessPolicyResourceType::ActionLogEntry => self.scoped_action_log_entry_id,
      AccessPolicyResourceType::App => self.scoped_app_id,
      AccessPolicyResourceType::AppAuthorization => self.scoped_app_authorization_id,
      AccessPolicyResourceType::AppAuthorizationCredential => self.scoped_app_authorization_credential_id,
      AccessPolicyResourceType::AppCredential => self.scoped_app_credential_id,
      AccessPolicyResourceType::Group => self.scoped_group_id,
      AccessPolicyResourceType::GroupMembership => self.scoped_group_membership_id,
      AccessPolicyResourceType::HTTPTransaction => self.scoped_http_transaction_id,
      AccessPolicyResourceType::Instance => None,
      AccessPolicyResourceType::Item => self.scoped_item_id,
      AccessPolicyResourceType::Milestone => self.scoped_milestone_id,
      AccessPolicyResourceType::Project => self.scoped_project_id,
      AccessPolicyResourceType::Role => self.scoped_role_id,
      AccessPolicyResourceType::RoleMembership => self.scoped_role_membership_id,
      AccessPolicyResourceType::ServerLogEntry => self.scoped_server_log_entry_id,
      AccessPolicyResourceType::Session => self.scoped_session_id,
      AccessPolicyResourceType::User => self.scoped_user_id,
      AccessPolicyResourceType::Workspace => self.scoped_workspace_id

    };
    
    loop {

      match selected_resource_type {

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
 
        },

        // ActionLogEntry -> Action
        AccessPolicyResourceType::ActionLogEntry => {

          let Some(scoped_action_log_entry_id) = self.scoped_action_log_entry_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ActionLogEntry));

          };

          hierarchy.push((AccessPolicyResourceType::ActionLogEntry, Some(scoped_action_log_entry_id)));

          let action_log_entry = match ActionLogEntry::get_by_id(&scoped_action_log_entry_id, postgres_client).await {

            Ok(action_log_entry) => action_log_entry,

            Err(error) => return Err(AccessPolicyError::ActionLogEntryError(error))

          };

          selected_resource_type = AccessPolicyResourceType::Action;
          selected_resource_id = Some(action_log_entry.action_id);

        },

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

        },

        // AppAuthorization -> (User | Workspace | Instance)
        AccessPolicyResourceType::AppAuthorization => {

          let Some(app_authorization_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppAuthorization));

          };

          hierarchy.push((AccessPolicyResourceType::AppAuthorization, Some(app_authorization_id)));

          let app_authorization = match AppAuthorization::get_by_id(&app_authorization_id, postgres_client).await {

            Ok(app_authorization) => app_authorization,

            Err(error) => match error {

              AppAuthorizationError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorization)),

              _ => return Err(AccessPolicyError::AppAuthorizationError(error))

            }

          };

          match app_authorization.parent_resource_type {

            AppAuthorizationParentResourceType::Instance => {

              selected_resource_type = AccessPolicyResourceType::Instance;
              selected_resource_id = None;

            },

            AppAuthorizationParentResourceType::Workspace => {

              let Some(workspace_id) = app_authorization.parent_workspace_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

              };

              selected_resource_type = AccessPolicyResourceType::Workspace;
              selected_resource_id = Some(workspace_id);

            },

            AppAuthorizationParentResourceType::User => {

              let Some(user_id) = app_authorization.parent_user_id else {

                return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

              };

              selected_resource_type = AccessPolicyResourceType::User;
              selected_resource_id = Some(user_id);

            }

          }

        },

        // AppAuthorizationCredential -> AppAuthorization
        AccessPolicyResourceType::AppAuthorizationCredential => {

          let Some(app_authorization_credential_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppAuthorizationCredential));

          };

          hierarchy.push((AccessPolicyResourceType::AppAuthorizationCredential, Some(app_authorization_credential_id)));

          let app_authorization_credential = match AppAuthorizationCredential::get_by_id(&app_authorization_credential_id, postgres_client).await {

            Ok(app_authorization_credential) => app_authorization_credential,

            Err(error) => match error {

              AppAuthorizationCredentialError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorizationCredential)),

              _ => return Err(AccessPolicyError::AppAuthorizationCredentialError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::AppAuthorization;
          selected_resource_id = Some(app_authorization_credential.app_authorization_id);

        },

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

        },

        // Group -> Instance
        AccessPolicyResourceType::Group => {

          let Some(group_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

          };

          hierarchy.push((AccessPolicyResourceType::Group, Some(group_id)));

          selected_resource_type = AccessPolicyResourceType::Instance;
          selected_resource_id = None;

        },

        // GroupMembership -> Group
        AccessPolicyResourceType::GroupMembership => {

          let Some(group_membership_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::GroupMembership));

          };

          hierarchy.push((AccessPolicyResourceType::GroupMembership, Some(group_membership_id)));

          let group_membership = match GroupMembership::get_by_id(&group_membership_id, postgres_client).await {

            Ok(group_membership) => group_membership,

            Err(error) => match error {

              GroupMembershipError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::GroupMembership)),

              _ => return Err(AccessPolicyError::GroupMembershipError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::Group;
          selected_resource_id = Some(group_membership.group_id);

        },

        // HTTPTransaction -> Instance
        AccessPolicyResourceType::HTTPTransaction => {

          let Some(http_transaction_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::HTTPTransaction));

          };

          hierarchy.push((AccessPolicyResourceType::HTTPTransaction, Some(http_transaction_id)));

          selected_resource_type = AccessPolicyResourceType::Instance;
          selected_resource_id = None;

        },
        
        // Instance
        AccessPolicyResourceType::Instance => break,

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

        // RoleMembership -> Role
        AccessPolicyResourceType::RoleMembership => {

          let Some(role_membership_id) = selected_resource_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::RoleMembership));

          };

          hierarchy.push((AccessPolicyResourceType::RoleMembership, Some(role_membership_id)));

          let role_membership = match RoleMembership::get_by_id(&role_membership_id, postgres_client).await {

            Ok(role_membership) => role_membership,

            Err(error) => match error {

              RoleMembershipError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::RoleMembership)),

              _ => return Err(AccessPolicyError::RoleMembershipError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::Role;
          selected_resource_id = Some(role_membership.role_id);

        }

        // ServerLogEntry -> Instance
        AccessPolicyResourceType::ServerLogEntry => {

          let Some(scoped_server_log_entry_id) = self.scoped_server_log_entry_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ServerLogEntry));

          };

          hierarchy.push((AccessPolicyResourceType::ServerLogEntry, Some(scoped_server_log_entry_id)));

          selected_resource_type = AccessPolicyResourceType::Instance;
          selected_resource_id = None;

        },

        // Session -> User
        AccessPolicyResourceType::Session => {

          let Some(scoped_session_id) = self.scoped_session_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Session));

          };

          hierarchy.push((AccessPolicyResourceType::Session, Some(scoped_session_id)));

          let session = match Session::get_by_id(&scoped_session_id, postgres_client).await {

            Ok(role_membership) => role_membership,

            Err(error) => match error {

              SessionError::NotFoundError(_) => return Err(AccessPolicyError::OrphanedResourceError(AccessPolicyResourceType::Session)),

              _ => return Err(AccessPolicyError::SessionError(error))

            }

          };

          selected_resource_type = AccessPolicyResourceType::User;
          selected_resource_id = Some(session.user_id);

        },

        // User -> Instance
        AccessPolicyResourceType::User => {

          let Some(scoped_user_id) = self.scoped_user_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

          };

          hierarchy.push((AccessPolicyResourceType::User, Some(scoped_user_id)));

        },

        // Workspace -> Instance
        AccessPolicyResourceType::Workspace => {

          let Some(scoped_workspace_id) = self.scoped_workspace_id else {

            return Err(AccessPolicyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

          };

          hierarchy.push((AccessPolicyResourceType::Workspace, Some(scoped_workspace_id)));

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