
/**
 * 
 * This module defines the implementation and types of an access policy.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
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
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError}, 
  utilities::slashstepql::{
    self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions
  }}
;

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
  "scoped_action_log_entry_id", 
  "scoped_app_id",
  "scoped_app_credential_id",
  "scoped_app_authorization_id",
  "scoped_app_authorization_credential_id",
  "scoped_field_id",
  "scoped_group_id", 
  "scoped_item_id", 
  "scoped_milestone_id", 
  "scoped_project_id", 
  "scoped_role_id", 
  "scoped_user_id", 
  "scoped_workspace_id",
  "permission_level",
  "is_inheritance_enabled"
];

pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "principal_user_id", 
  "principal_group_id", 
  "principal_role_id", 
  "principal_app_id",
  "scoped_action_id", 
  "scoped_action_log_entry_id",
  "scoped_app_id",
  "scoped_app_authorization_id",
  "scoped_app_authorization_credential_id",
  "scoped_field_id",
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
pub enum ActionPermissionLevel {
  #[default]
  None,
  User,
  Editor,
  Admin
}

impl fmt::Display for ActionPermissionLevel {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ActionPermissionLevel::None => write!(f, "None"),
      ActionPermissionLevel::User => write!(f, "User"),
      ActionPermissionLevel::Editor => write!(f, "Editor"),
      ActionPermissionLevel::Admin => write!(f, "Admin")
    }
  }
}

impl FromStr for ActionPermissionLevel {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "None" => Ok(ActionPermissionLevel::None),
      "User" => Ok(ActionPermissionLevel::User),
      "Editor" => Ok(ActionPermissionLevel::Editor),
      "Admin" => Ok(ActionPermissionLevel::Admin),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }
    
  }

}

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize)]
#[postgres(name = "resource_type")]
pub enum ResourceType {
  AccessPolicy,
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Group,
  GroupMembership,
  HTTPTransaction,
  Server,
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

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default)]
#[postgres(name = "access_policy_resource_type")]
pub enum AccessPolicyResourceType {
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Field,
  Group,
  GroupMembership,
  HTTPTransaction,
  #[default]
  Server,
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
      AccessPolicyResourceType::Field => write!(formatter, "Field"),
      AccessPolicyResourceType::Group => write!(formatter, "Group"),
      AccessPolicyResourceType::GroupMembership => write!(formatter, "GroupMembership"),
      AccessPolicyResourceType::HTTPTransaction => write!(formatter, "HTTPTransaction"),
      AccessPolicyResourceType::Server => write!(formatter, "Server"),
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

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Action" => Ok(AccessPolicyResourceType::Action),
      "ActionLogEntry" => Ok(AccessPolicyResourceType::ActionLogEntry),
      "App" => Ok(AccessPolicyResourceType::App),
      "AppAuthorization" => Ok(AccessPolicyResourceType::AppAuthorization),
      "AppAuthorizationCredential" => Ok(AccessPolicyResourceType::AppAuthorizationCredential),
      "AppCredential" => Ok(AccessPolicyResourceType::AppCredential),
      "Field" => Ok(AccessPolicyResourceType::Field),
      "Group" => Ok(AccessPolicyResourceType::Group),
      "GroupMembership" => Ok(AccessPolicyResourceType::GroupMembership),
      "HTTPTransaction" => Ok(AccessPolicyResourceType::HTTPTransaction),
      "Server" => Ok(AccessPolicyResourceType::Server),
      "Item" => Ok(AccessPolicyResourceType::Item),
      "Milestone" => Ok(AccessPolicyResourceType::Milestone),
      "Project" => Ok(AccessPolicyResourceType::Project),
      "Role" => Ok(AccessPolicyResourceType::Role),
      "RoleMembership" => Ok(AccessPolicyResourceType::RoleMembership),
      "ServerLogEntry" => Ok(AccessPolicyResourceType::ServerLogEntry),
      "Session" => Ok(AccessPolicyResourceType::Session),
      "User" => Ok(AccessPolicyResourceType::User),
      "Workspace" => Ok(AccessPolicyResourceType::Workspace),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }

  }

}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default, Clone, Copy)]
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

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "App" => Ok(AccessPolicyPrincipalType::App),
      "Group" => Ok(AccessPolicyPrincipalType::Group),
      "Role" => Ok(AccessPolicyPrincipalType::Role),
      "User" => Ok(AccessPolicyPrincipalType::User),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
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

#[derive(Debug, Deserialize, Default)]
pub struct InitialAccessPolicyProperties {

  pub action_id: Uuid,

  pub permission_level: ActionPermissionLevel,

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

  pub scoped_field_id: Option<Uuid>,

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

  pub permission_level: Option<ActionPermissionLevel>,

  pub is_inheritance_enabled: Option<bool>,

}

pub type ResourceHierarchy = Vec<(AccessPolicyResourceType, Option<Uuid>)>;

#[derive(Debug, Clone)]
pub enum IndividualPrincipal {
  User(Uuid),
  App(Uuid)
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct InitialAccessPolicyPropertiesForPredefinedScope {
  pub action_id: Uuid,
  pub permission_level: ActionPermissionLevel,
  pub is_inheritance_enabled: bool,
  pub principal_type: AccessPolicyPrincipalType,
  pub principal_user_id: Option<Uuid>,
  pub principal_group_id: Option<Uuid>,
  pub principal_role_id: Option<Uuid>,
  pub principal_app_id: Option<Uuid>
}

/// A piece of information that defines the level of access and inheritance for a principal to perform an action.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessPolicy {

  /// The access policy's ID.
  pub id: Uuid,
  
  /// The action ID that this access policy refers to.
  pub action_id: Uuid,

  pub permission_level: ActionPermissionLevel,

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

  pub scoped_field_id: Option<Uuid>,

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
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, ResourceError> {

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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "AccessPolicy", "access_policies", "slashstep.accessPolicies.get", true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let database_client = database_pool.get().await?;
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new access policy.
  pub async fn create(initial_properties: &InitialAccessPolicyProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/access_policies/insert_access_policy_row.sql");
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
      &initial_properties.scoped_field_id,
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
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => {

        match db_error.code() {

          &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError("An access policy with the same scope and action ID already exists.".to_string()),
          
          _ => ResourceError::PostgresError(error)

        }

      },

      None => ResourceError::PostgresError(error)
    
    })?;

    let access_policy = AccessPolicy::convert_from_row(&row);

    return Ok(access_policy);

  }

  /// Gets an access policy by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/access_policies/get_access_policy_row_by_id.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[&id];
    let database_client = database_pool.get().await?;
    let row = match database_client.query_opt(query, parameters).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An access policy with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

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
      scoped_field_id: row.get("scoped_field_id"),
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
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let table_query = include_str!("../../queries/access_policies/initialize_access_policies_table.sql");
    database_client.execute(table_query, &[]).await?;

    let get_prinicipal_access_policies_function = include_str!("../../queries/access_policies/create_function_get_principal_access_policies.sql");
    database_client.execute(get_prinicipal_access_policies_function, &[]).await?;

    let can_principal_get_access_policy_function = include_str!("../../queries/access_policies/create_function_can_principal_get_resource.sql");
    database_client.execute(can_principal_get_access_policy_function, &[]).await?;

    let get_initial_resource_id_from_access_policy_function = include_str!("../../queries/access_policies/create_function_get_initial_resource_id_from_access_policy.sql");
    database_client.execute(get_initial_resource_id_from_access_policy_function, &[]).await?;

    return Ok(());

  }

  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {

        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))

      };

      return Ok(Box::new(uuid));

    } else {

      match key {

        "scoped_resource_type" => {

          let scoped_resource_type = match AccessPolicyResourceType::from_str(value) {

            Ok(scoped_resource_type) => scoped_resource_type,
            Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

          };

          return Ok(Box::new(scoped_resource_type));

        },
        
        "principal_type" => {

          let principal_type = match AccessPolicyPrincipalType::from_str(value) {

            Ok(principal_type) => principal_type,
            Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

          };

          return Ok(Box::new(principal_type));

        },

        "permission_level" => {

          let permission_level = match ActionPermissionLevel::from_str(value) {

            Ok(permission_level) => permission_level,
            Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

          };
          
          return Ok(Box::new(permission_level));

        },

        _ => {

          return Ok(Box::new(value));

        }

      }

    }

  }

  /// Returns a list of access policies based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {
                            
    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ACCESS_POLICY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_ACCESS_POLICY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = match SlashstepQLFilterSanitizer::sanitize(&sanitizer_options) {
      Ok(sanitized_filter) => sanitized_filter,
      Err(error) => {
       
        return Err(ResourceError::SlashstepQLError(error))

      }
    };
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "AccessPolicy", "access_policies", "slashstep.accessPolicies.get", false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let access_policies = rows.iter().map(AccessPolicy::convert_from_row).collect();
    return Ok(access_policies);

  }

  /// Returns a list of access policies based on a hierarchy.
  pub async fn list_by_hierarchy(principal: &Principal, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, database_pool: &deadpool_postgres::Pool) -> Result<Vec<Self>, ResourceError> {

    let mut query_clauses: Vec<String> = Vec::new();

    for (resource_type, resource_id) in resource_hierarchy {

      if *resource_type == AccessPolicyResourceType::Server {

        query_clauses.push(format!("scoped_resource_type = 'Server'"));
        continue;

      }

      let resource_id = match resource_id {

        Some(resource_id) => resource_id,

        None => {
          
          let error_string = match resource_type {
            
            AccessPolicyResourceType::Action => "An action ID must be provided.",
            AccessPolicyResourceType::ActionLogEntry => "An action log entry ID must be provided.",
            AccessPolicyResourceType::App => "An app ID must be provided.",
            AccessPolicyResourceType::AppAuthorization => "An app authorization ID must be provided.",
            AccessPolicyResourceType::AppAuthorizationCredential => "An app authorization credential ID must be provided.",
            AccessPolicyResourceType::AppCredential => "An app credential ID must be provided.",
            AccessPolicyResourceType::Field => "A field ID must be provided.",
            AccessPolicyResourceType::Group => "A group ID must be provided.",
            AccessPolicyResourceType::GroupMembership => "A group membership ID must be provided.",
            AccessPolicyResourceType::HTTPTransaction => "An HTTP transaction ID must be provided.",
            AccessPolicyResourceType::Server => "An server ID must be provided.", // Huh??
            AccessPolicyResourceType::Item => "An item ID must be provided.",
            AccessPolicyResourceType::Milestone => "A milestone ID must be provided.",
            AccessPolicyResourceType::Project => "A project ID must be provided.",
            AccessPolicyResourceType::Role => "A role ID must be provided.",
            AccessPolicyResourceType::RoleMembership => "A role membership ID must be provided.",
            AccessPolicyResourceType::ServerLogEntry => "A server log entry ID must be provided.",
            AccessPolicyResourceType::Session => "A session ID must be provided.",
            AccessPolicyResourceType::User => "A user ID must be provided.",
            AccessPolicyResourceType::Workspace => "A workspace ID must be provided."

          };

          return Err(ResourceError::HierarchyResourceIDMissingError(error_string.to_string()));

        }

      };

      let resource_id_as_quote_literal = quote_literal(&format!("{}", resource_id));
      match resource_type {

        AccessPolicyResourceType::Action => query_clauses.push(format!("scoped_action_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::ActionLogEntry => query_clauses.push(format!("scoped_action_log_entry_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::App => query_clauses.push(format!("scoped_app_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::AppAuthorization => query_clauses.push(format!("scoped_app_authorization_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::AppAuthorizationCredential => query_clauses.push(format!("scoped_app_authorization_credential_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::AppCredential => query_clauses.push(format!("scoped_app_credential_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Group => query_clauses.push(format!("scoped_group_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::GroupMembership => query_clauses.push(format!("scoped_group_membership_id = {}", resource_id_as_quote_literal)), 
        AccessPolicyResourceType::HTTPTransaction => query_clauses.push(format!("scoped_http_transaction_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Item => query_clauses.push(format!("scoped_item_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Milestone => query_clauses.push(format!("scoped_milestone_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Project => query_clauses.push(format!("scoped_project_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Role => query_clauses.push(format!("scoped_role_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::RoleMembership => query_clauses.push(format!("scoped_role_membership_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::ServerLogEntry => query_clauses.push(format!("scoped_server_log_entry_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Session => query_clauses.push(format!("scoped_session_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::User => query_clauses.push(format!("scoped_user_id = {}", resource_id_as_quote_literal)),
        AccessPolicyResourceType::Workspace => query_clauses.push(format!("scoped_workspace_id = {}", resource_id_as_quote_literal)),
        _ => {}

      }

    }

    // This will turn the query into something like:
    // action_id = $1 and (scoped_resource_type = 'Server' or scoped_workspace_id = $2 or scoped_project_id = $3 or scoped_milestone_id = $4 or scoped_item_id = $5)
    let principal_clause = match principal {

      Principal::User(user_id) => format!("principal_user_id = '{}'", user_id),
      Principal::Group(group_id) => format!("principal_group_id = '{}'", group_id),
      Principal::Role(role_id) => format!("principal_role_id = '{}'", role_id),
      Principal::App(app_id) => format!("principal_app_id = '{}'", app_id)

    };
    let mut query_filter = String::new();
    query_filter.push_str(format!("{} AND action_id = {} AND (", principal_clause, quote_literal(&action_id.to_string())).as_str());
    for i in 0..query_clauses.len() {

      if i > 0 {

        query_filter.push_str(" OR ");

      }

      query_filter.push_str(&query_clauses[i]);

    }
    query_filter.push_str(")");
    
    let access_policies = AccessPolicy::list(&query_filter, database_pool, None).await?;

    return Ok(access_policies);

  }

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: Option<&T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    let parameter_value = parameter_value.and_then(|parameter_value| Some(parameter_value.clone()));
    if let Some(parameter_value) = parameter_value {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  /// Updates this access policy and returns a new instance of the access policy.
  pub async fn update(&self, properties: &EditableAccessPolicyProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("update access_policies set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "permission_level", Some(&properties.permission_level));
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "is_inheritance_enabled", Some(&properties.is_inheritance_enabled));

    query.push_str(format!(" where id = ${} returning *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("commit;", &[]).await?;

    let access_policy = AccessPolicy::convert_from_row(&row);
    return Ok(access_policy);

  }

  pub fn get_scoped_resource_id(&self) -> Option<Uuid> {

    let scoped_resource_id = match self.scoped_resource_type {

      AccessPolicyResourceType::Action => self.scoped_action_id,
      AccessPolicyResourceType::ActionLogEntry => self.scoped_action_log_entry_id,
      AccessPolicyResourceType::App => self.scoped_app_id,
      AccessPolicyResourceType::AppAuthorization => self.scoped_app_authorization_id,
      AccessPolicyResourceType::AppAuthorizationCredential => self.scoped_app_authorization_credential_id,
      AccessPolicyResourceType::AppCredential => self.scoped_app_credential_id,
      AccessPolicyResourceType::Field => self.scoped_field_id,
      AccessPolicyResourceType::Group => self.scoped_group_id,
      AccessPolicyResourceType::GroupMembership => self.scoped_group_membership_id,
      AccessPolicyResourceType::HTTPTransaction => self.scoped_http_transaction_id,
      AccessPolicyResourceType::Server => None,
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

    return scoped_resource_id;

  }

}

impl DeletableResource for AccessPolicy {

  /// Deletes this access policy.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/access_policies/delete_access_policy_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}

#[cfg(test)]
mod tests;