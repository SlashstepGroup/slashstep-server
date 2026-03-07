
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

#[cfg(test)]
mod tests;

use core::{fmt};
use std::str::FromStr;
use postgres::{
  error::SqlState, 
  types::ToSql
};
use postgres_types::FromSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError}, 
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
  "scoped_access_policy_id",
  "scoped_action_id", 
  "scoped_action_log_entry_id",
  "scoped_app_id",
  "scoped_app_authorization_id",
  "scoped_app_authorization_credential_id",
  "scoped_app_credential_id",
  "scoped_configuration_id",
  "scoped_delegation_policy_id",
  "scoped_field_id",
  "scoped_field_choice_id",
  "scoped_field_value_id",
  "scoped_group_id",
  "scoped_http_transaction_id",
  "scoped_item_id",
  "scoped_item_connection_id",
  "scoped_item_connection_type_id",
  "scoped_item_type_id",
  "scoped_item_type_icon_id",
  "scoped_iteration_id",
  "scoped_membership_id",
  "scoped_membership_invitation_id",
  "scoped_milestone_id", 
  "scoped_oauth_authorization_id",
  "scoped_project_id", 
  "scoped_role_id",
  "scoped_server_log_entry_id",
  "scoped_session_id",
  "scoped_status_id",
  "scoped_user_id", 
  "scoped_view_id",
  "scoped_view_field_id",
  "scoped_webhook_id",
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
  "scoped_access_policy_id",
  "scoped_action_id", 
  "scoped_action_log_entry_id",
  "scoped_app_id",
  "scoped_app_authorization_id",
  "scoped_app_authorization_credential_id",
  "scoped_app_credential_id",
  "scoped_configuration_id",
  "scoped_delegation_policy_id",
  "scoped_field_id",
  "scoped_field_choice_id",
  "scoped_field_value_id",
  "scoped_group_id",
  "scoped_http_transaction_id",
  "scoped_item_id",
  "scoped_item_connection_id",
  "scoped_item_connection_type_id",
  "scoped_item_type_id",
  "scoped_item_type_icon_id",
  "scoped_iteration_id",
  "scoped_membership_id",
  "scoped_membership_invitation_id",
  "scoped_milestone_id", 
  "scoped_oauth_authorization_id",
  "scoped_project_id", 
  "scoped_role_id",
  "scoped_server_log_entry_id",
  "scoped_session_id",
  "scoped_status_id",
  "scoped_user_id", 
  "scoped_view_id",
  "scoped_view_field_id",
  "scoped_webhook_id",
  "scoped_workspace_id"
];

pub const DEFAULT_ACCESS_POLICY_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;

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

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default, Copy)]
#[postgres(name = "resource_type")]
pub enum ResourceType {
  AccessPolicy,
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Configuration,
  DelegationPolicy,
  FieldValue,
  Field,
  FieldChoice,
  Group,
  HTTPTransaction,
  #[default]
  Server,
  Item,
  ItemConnection,
  ItemConnectionType,
  ItemType,
  ItemTypeIcon,
  Iteration,
  Membership,
  MembershipInvitation,
  Milestone,
  OAuthAuthorization,
  Project,
  Role,
  ServerLogEntry,
  Session,
  Status,
  User,
  View,
  ViewField,
  Webhook,
  Workspace
}

impl fmt::Display for ResourceType {
  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ResourceType::AccessPolicy => write!(formatter, "AccessPolicy"),
      ResourceType::Action => write!(formatter, "Action"),
      ResourceType::ActionLogEntry => write!(formatter, "ActionLogEntry"),
      ResourceType::App => write!(formatter, "App"),
      ResourceType::AppAuthorization => write!(formatter, "AppAuthorization"),
      ResourceType::AppAuthorizationCredential => write!(formatter, "AppAuthorizationCredential"),
      ResourceType::AppCredential => write!(formatter, "AppCredential"),
      ResourceType::Configuration => write!(formatter, "Configuration"),
      ResourceType::DelegationPolicy => write!(formatter, "DelegationPolicy"),
      ResourceType::Field => write!(formatter, "Field"),
      ResourceType::FieldChoice => write!(formatter, "FieldChoice"),
      ResourceType::FieldValue => write!(formatter, "FieldValue"),
      ResourceType::Group => write!(formatter, "Group"),
      ResourceType::HTTPTransaction => write!(formatter, "HTTPTransaction"),
      ResourceType::Server => write!(formatter, "Server"),
      ResourceType::Item => write!(formatter, "Item"),
      ResourceType::ItemConnection => write!(formatter, "ItemConnection"),
      ResourceType::ItemConnectionType => write!(formatter, "ItemConnectionType"),
      ResourceType::ItemType => write!(formatter, "ItemType"),
      ResourceType::ItemTypeIcon => write!(formatter, "ItemTypeIcon"),
      ResourceType::Iteration => write!(formatter, "Iteration"),
      ResourceType::Membership => write!(formatter, "Membership"),
      ResourceType::MembershipInvitation => write!(formatter, "MembershipInvitation"),
      ResourceType::Milestone => write!(formatter, "Milestone"),
      ResourceType::OAuthAuthorization => write!(formatter, "OAuthAuthorization"),
      ResourceType::Project => write!(formatter, "Project"),
      ResourceType::Role => write!(formatter, "Role"),
      ResourceType::ServerLogEntry => write!(formatter, "ServerLogEntry"),
      ResourceType::Session => write!(formatter, "Session"),
      ResourceType::Status => write!(formatter, "Status"),
      ResourceType::User => write!(formatter, "User"),
      ResourceType::View => write!(formatter, "View"),
      ResourceType::ViewField => write!(formatter, "ViewField"),
      ResourceType::Webhook => write!(formatter, "Webhook"),
      ResourceType::Workspace => write!(formatter, "Workspace")
    }
  }
}

impl FromStr for ResourceType {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "AccessPolicy" => Ok(ResourceType::AccessPolicy),
      "Action" => Ok(ResourceType::Action),
      "ActionLogEntry" => Ok(ResourceType::ActionLogEntry),
      "App" => Ok(ResourceType::App),
      "AppAuthorization" => Ok(ResourceType::AppAuthorization),
      "AppAuthorizationCredential" => Ok(ResourceType::AppAuthorizationCredential),
      "AppCredential" => Ok(ResourceType::AppCredential),
      "Configuration" => Ok(ResourceType::Configuration),
      "DelegationPolicy" => Ok(ResourceType::DelegationPolicy),
      "Field" => Ok(ResourceType::Field),
      "FieldChoice" => Ok(ResourceType::FieldChoice),
      "FieldValue" => Ok(ResourceType::FieldValue),
      "Group" => Ok(ResourceType::Group),
      "HTTPTransaction" => Ok(ResourceType::HTTPTransaction),
      "Server" => Ok(ResourceType::Server),
      "Item" => Ok(ResourceType::Item),
      "ItemConnection" => Ok(ResourceType::ItemConnection),
      "ItemConnectionType" => Ok(ResourceType::ItemConnectionType),
      "ItemType" => Ok(ResourceType::ItemType),
      "ItemTypeIcon" => Ok(ResourceType::ItemTypeIcon),
      "Iteration" => Ok(ResourceType::Iteration),
      "Membership" => Ok(ResourceType::Membership),
      "MembershipInvitation" => Ok(ResourceType::MembershipInvitation),
      "Milestone" => Ok(ResourceType::Milestone),
      "OAuthAuthorization" => Ok(ResourceType::OAuthAuthorization),
      "Project" => Ok(ResourceType::Project),
      "Role" => Ok(ResourceType::Role),
      "ServerLogEntry" => Ok(ResourceType::ServerLogEntry),
      "Session" => Ok(ResourceType::Session),
      "Status" => Ok(ResourceType::Status),
      "User" => Ok(ResourceType::User),
      "View" => Ok(ResourceType::View),
      "ViewField" => Ok(ResourceType::ViewField),
      "Webhook" => Ok(ResourceType::Webhook),
      "Workspace" => Ok(ResourceType::Workspace),
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

  pub scoped_resource_type: ResourceType,

  pub scoped_access_policy_id: Option<Uuid>,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_action_log_entry_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_app_authorization_id: Option<Uuid>,

  pub scoped_app_authorization_credential_id: Option<Uuid>,

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_configuration_id: Option<Uuid>,

  pub scoped_delegation_policy_id: Option<Uuid>,

  pub scoped_field_id: Option<Uuid>,

  pub scoped_field_choice_id: Option<Uuid>,

  pub scoped_field_value_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_http_transaction_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_item_connection_id: Option<Uuid>,

  pub scoped_item_connection_type_id: Option<Uuid>,

  pub scoped_item_type_id: Option<Uuid>,

  pub scoped_item_type_icon_id: Option<Uuid>,

  pub scoped_iteration_id: Option<Uuid>,

  pub scoped_membership_id: Option<Uuid>,

  pub scoped_membership_invitation_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_oauth_authorization_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_server_log_entry_id: Option<Uuid>,

  pub scoped_session_id: Option<Uuid>,

  pub scoped_status_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_view_id: Option<Uuid>,

  pub scoped_view_field_id: Option<Uuid>,

  pub scoped_webhook_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EditableAccessPolicyProperties {

  pub permission_level: Option<ActionPermissionLevel>,

  pub is_inheritance_enabled: Option<bool>,

}

#[derive(Debug, Clone)]
pub enum PrincipalWithID {
  User(Uuid),
  App(Uuid),
  Group(Uuid),
  Role(Uuid)
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

  pub scoped_resource_type: ResourceType,

  pub scoped_access_policy_id: Option<Uuid>,

  pub scoped_action_id: Option<Uuid>,

  pub scoped_action_log_entry_id: Option<Uuid>,

  pub scoped_app_id: Option<Uuid>,

  pub scoped_app_authorization_id: Option<Uuid>,

  pub scoped_app_authorization_credential_id: Option<Uuid>,

  pub scoped_app_credential_id: Option<Uuid>,

  pub scoped_configuration_id: Option<Uuid>,

  pub scoped_field_id: Option<Uuid>,

  pub scoped_field_choice_id: Option<Uuid>,

  pub scoped_field_value_id: Option<Uuid>,

  pub scoped_delegation_policy_id: Option<Uuid>,

  pub scoped_group_id: Option<Uuid>,

  pub scoped_http_transaction_id: Option<Uuid>,

  pub scoped_item_id: Option<Uuid>,

  pub scoped_item_connection_id: Option<Uuid>,

  pub scoped_item_connection_type_id: Option<Uuid>,

  pub scoped_item_type_id: Option<Uuid>,

  pub scoped_item_type_icon_id: Option<Uuid>,

  pub scoped_iteration_id: Option<Uuid>,

  pub scoped_membership_id: Option<Uuid>,

  pub scoped_membership_invitation_id: Option<Uuid>,

  pub scoped_milestone_id: Option<Uuid>,

  pub scoped_oauth_authorization_id: Option<Uuid>,

  pub scoped_project_id: Option<Uuid>,

  pub scoped_role_id: Option<Uuid>,

  pub scoped_server_log_entry_id: Option<Uuid>,

  pub scoped_session_id: Option<Uuid>,

  pub scoped_status_id: Option<Uuid>,

  pub scoped_user_id: Option<Uuid>,

  pub scoped_view_id: Option<Uuid>,

  pub scoped_view_field_id: Option<Uuid>,

  pub scoped_webhook_id: Option<Uuid>,

  pub scoped_workspace_id: Option<Uuid>

}

impl AccessPolicy {

  /* Static methods */
  /// Counts the number of access policies based on a query.
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<i64, ResourceError> {

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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, "AccessPolicy", "access_policies", "accessPolicies.get", true)?;
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
      &initial_properties.scoped_access_policy_id,
      &initial_properties.scoped_action_id,
      &initial_properties.scoped_action_log_entry_id,
      &initial_properties.scoped_app_id,
      &initial_properties.scoped_app_authorization_id,
      &initial_properties.scoped_app_authorization_credential_id,
      &initial_properties.scoped_app_credential_id,
      &initial_properties.scoped_configuration_id,
      &initial_properties.scoped_delegation_policy_id,
      &initial_properties.scoped_field_id,
      &initial_properties.scoped_field_choice_id,
      &initial_properties.scoped_field_value_id,
      &initial_properties.scoped_group_id,
      &initial_properties.scoped_http_transaction_id,
      &initial_properties.scoped_item_id,
      &initial_properties.scoped_item_connection_id,
      &initial_properties.scoped_item_connection_type_id,
      &initial_properties.scoped_item_type_id,
      &initial_properties.scoped_item_type_icon_id,
      &initial_properties.scoped_iteration_id,
      &initial_properties.scoped_membership_id,
      &initial_properties.scoped_membership_invitation_id,
      &initial_properties.scoped_milestone_id,
      &initial_properties.scoped_oauth_authorization_id,
      &initial_properties.scoped_project_id,
      &initial_properties.scoped_role_id,
      &initial_properties.scoped_server_log_entry_id,
      &initial_properties.scoped_session_id,
      &initial_properties.scoped_status_id,
      &initial_properties.scoped_user_id,
      &initial_properties.scoped_view_id,
      &initial_properties.scoped_view_field_id,
      &initial_properties.scoped_webhook_id,
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

  /// Deletes this access policy.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/access_policies/delete_access_policy_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

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
      scoped_access_policy_id: row.get("scoped_access_policy_id"),
      scoped_action_id: row.get("scoped_action_id"),
      scoped_action_log_entry_id: row.get("scoped_action_log_entry_id"),
      scoped_app_id: row.get("scoped_app_id"),
      scoped_app_authorization_id: row.get("scoped_app_authorization_id"),
      scoped_app_authorization_credential_id: row.get("scoped_app_authorization_credential_id"),
      scoped_app_credential_id: row.get("scoped_app_credential_id"),
      scoped_configuration_id: row.get("scoped_configuration_id"),
      scoped_delegation_policy_id: row.get("scoped_delegation_policy_id"),
      scoped_field_id: row.get("scoped_field_id"),
      scoped_field_choice_id: row.get("scoped_field_choice_id"),
      scoped_field_value_id: row.get("scoped_field_value_id"),
      scoped_group_id: row.get("scoped_group_id"),
      scoped_http_transaction_id: row.get("scoped_http_transaction_id"),
      scoped_item_id: row.get("scoped_item_id"),
      scoped_item_connection_id: row.get("scoped_item_connection_id"),
      scoped_item_connection_type_id: row.get("scoped_item_connection_type_id"),
      scoped_item_type_id: row.get("scoped_item_type_id"),
      scoped_item_type_icon_id: row.get("scoped_item_type_icon_id"),
      scoped_iteration_id: row.get("scoped_iteration_id"),
      scoped_membership_id: row.get("scoped_membership_id"),
      scoped_membership_invitation_id: row.get("scoped_membership_invitation_id"),
      scoped_milestone_id: row.get("scoped_milestone_id"),
      scoped_oauth_authorization_id: row.get("scoped_oauth_authorization_id"),
      scoped_project_id: row.get("scoped_project_id"),
      scoped_role_id: row.get("scoped_role_id"),
      scoped_server_log_entry_id: row.get("scoped_server_log_entry_id"),
      scoped_session_id: row.get("scoped_session_id"),
      scoped_status_id: row.get("scoped_status_id"),
      scoped_user_id: row.get("scoped_user_id"),
      scoped_view_id: row.get("scoped_view_id"),
      scoped_view_field_id: row.get("scoped_view_field_id"),
      scoped_webhook_id: row.get("scoped_webhook_id"),
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

    let get_principal_permission_level_function = include_str!("../../queries/access_policies/create_function_get_principal_permission_level.sql");
    database_client.execute(get_principal_permission_level_function, &[]).await?;

    let get_scoped_resource_id_from_access_policy_function = include_str!("../../queries/access_policies/create_function_get_scoped_resource_id_from_access_policy.sql");
    database_client.execute(get_scoped_resource_id_from_access_policy_function, &[]).await?;

    return Ok(());

  }

  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {

        Ok(uuid) => uuid,
        Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\": {}", value, key, error)))

      };

      return Ok(Box::new(uuid));

    } else {

      match key {

        "scoped_resource_type" => {

          let scoped_resource_type = match ResourceType::from_str(value) {

            Ok(scoped_resource_type) => scoped_resource_type,
            Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\": {}", value, key, error)))

          };

          return Ok(Box::new(scoped_resource_type));

        },
        
        "principal_type" => {

          let principal_type = match AccessPolicyPrincipalType::from_str(value) {

            Ok(principal_type) => principal_type,
            Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\": {}", value, key, error)))

          };

          return Ok(Box::new(principal_type));

        },

        "permission_level" => {

          let permission_level = match ActionPermissionLevel::from_str(value) {

            Ok(permission_level) => permission_level,
            Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\": {}", value, key, error)))

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
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {
                            
    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ACCESS_POLICY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = match SlashstepQLFilterSanitizer::sanitize(&sanitizer_options) {
      Ok(sanitized_filter) => sanitized_filter,
      Err(error) => {
       
        return Err(ResourceError::SlashstepQLError(error))

      }
    };
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, "AccessPolicy", "access_policies", "accessPolicies.get", false)?;
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    
    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let access_policies = rows.iter().map(AccessPolicy::convert_from_row).collect();
    return Ok(access_policies);

  }

  /// Updates this access policy and returns a new instance of the access policy.
  pub async fn update(&self, properties: &EditableAccessPolicyProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("update access_policies set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "permission_level", Some(&properties.permission_level));
    let (mut parameter_boxes, mut query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "is_inheritance_enabled", Some(&properties.is_inheritance_enabled));

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

      ResourceType::AccessPolicy => self.scoped_access_policy_id,
      ResourceType::Action => self.scoped_action_id,
      ResourceType::ActionLogEntry => self.scoped_action_log_entry_id,
      ResourceType::App => self.scoped_app_id,
      ResourceType::AppAuthorization => self.scoped_app_authorization_id,
      ResourceType::AppAuthorizationCredential => self.scoped_app_authorization_credential_id,
      ResourceType::AppCredential => self.scoped_app_credential_id,
      ResourceType::Configuration => self.scoped_configuration_id,
      ResourceType::DelegationPolicy => self.scoped_delegation_policy_id,
      ResourceType::Field => self.scoped_field_id,
      ResourceType::FieldChoice => self.scoped_field_choice_id,
      ResourceType::FieldValue => self.scoped_field_value_id,
      ResourceType::Group => self.scoped_group_id,
      ResourceType::HTTPTransaction => self.scoped_http_transaction_id,
      ResourceType::Server => None,
      ResourceType::Item => self.scoped_item_id,
      ResourceType::ItemConnection => self.scoped_item_connection_id,
      ResourceType::ItemConnectionType => self.scoped_item_connection_type_id,
      ResourceType::ItemType => self.scoped_item_type_id,
      ResourceType::ItemTypeIcon => self.scoped_item_type_icon_id,
      ResourceType::Iteration => self.scoped_iteration_id,
      ResourceType::Membership => self.scoped_membership_id,
      ResourceType::MembershipInvitation => self.scoped_membership_invitation_id,
      ResourceType::Milestone => self.scoped_milestone_id,
      ResourceType::OAuthAuthorization => self.scoped_oauth_authorization_id,
      ResourceType::Project => self.scoped_project_id,
      ResourceType::Role => self.scoped_role_id,
      ResourceType::ServerLogEntry => self.scoped_server_log_entry_id,
      ResourceType::Session => self.scoped_session_id,
      ResourceType::Status => self.scoped_session_id,
      ResourceType::User => self.scoped_user_id,
      ResourceType::View => self.scoped_view_id,
      ResourceType::ViewField => self.scoped_view_field_id,
      ResourceType::Webhook => self.scoped_webhook_id,
      ResourceType::Workspace => self.scoped_workspace_id

    };

    return scoped_resource_id;

  }

}