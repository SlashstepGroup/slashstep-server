use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "http_transaction_id",
  "actor_type",
  "actor_user_id",
  "actor_app_id",
  "target_resource_type",
  "target_access_policy_id",
  "target_action_id",
  "target_action_log_entry_id",
  "target_app_id",
  "target_app_authorization_id",
  "target_app_authorization_credential_id",
  "target_app_credential_id",
  "target_group_id",
  "target_group_membership_id",
  "target_http_transaction_id",
  "target_item_id",
  "target_milestone_id",
  "target_project_id",
  "target_role_id",
  "target_role_membership_id",
  "target_server_log_entry_id",
  "target_session_id",
  "target_user_id",
  "target_workspace_id",
  "reason"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "http_transaction_id",
  "actor_user_id",
  "actor_app_id",
  "target_resource_type",
  "target_access_policy_id",
  "target_action_id",
  "target_action_log_entry_id",
  "target_app_id",
  "target_app_authorization_id",
  "target_app_authorization_credential_id",
  "target_app_credential_id",
  "target_group_id",
  "target_group_membership_id",
  "target_http_transaction_id",
  "target_item_id",
  "target_milestone_id",
  "target_project_id",
  "target_role_id",
  "target_role_membership_id",
  "target_server_log_entry_id",
  "target_session_id",
  "target_user_id",
  "target_workspace_id"
];

#[derive(Debug, Clone, FromSql, ToSql, Serialize, Deserialize, Default, PartialEq, Eq)]
#[postgres(name = "action_log_entry_actor_type")]
pub enum ActionLogEntryActorType {
  #[default]
  User,
  App
}

#[derive(Debug, Clone, FromSql, ToSql, Serialize, Deserialize, Default, PartialEq, Eq)]
#[postgres(name = "action_log_entry_target_resource_type")]
pub enum ActionLogEntryTargetResourceType {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {

  /// The ID of the action log entry.
  pub id: Uuid,

  /// The ID of the action.
  pub action_id: Uuid,

  /// The ID of the HTTP transaction related to the action log entry, if applicable.
  pub http_transaction_id: Option<Uuid>,

  /// The type of actor that performed the action.
  pub actor_type: ActionLogEntryActorType,

  /// The ID of the user actor that performed the action, if applicable.
  pub actor_user_id: Option<Uuid>,

  /// The ID of the app actor that performed the action, if applicable.
  pub actor_app_id: Option<Uuid>,

  /// The type of the target resource of the action.
  pub target_resource_type: ActionLogEntryTargetResourceType,

  /// The target access policy ID of the action, if applicable.
  pub target_access_policy_id: Option<Uuid>,

  /// The target action ID of the action, if applicable.
  pub target_action_id: Option<Uuid>,

  /// The target action log entry ID of the action, if applicable.
  pub target_action_log_entry_id: Option<Uuid>,

  /// The target app ID of the action, if applicable.
  pub target_app_id: Option<Uuid>,

  /// The target app authorization ID of the action, if applicable.
  pub target_app_authorization_id: Option<Uuid>,

  /// The target app authorization credential ID of the action, if applicable.
  pub target_app_authorization_credential_id: Option<Uuid>,

  /// The target app credential ID of the action, if applicable.
  pub target_app_credential_id: Option<Uuid>,

  /// The target group ID of the action, if applicable.
  pub target_group_id: Option<Uuid>,

  /// The target group membership ID of the action, if applicable.
  pub target_group_membership_id: Option<Uuid>,

  /// The target HTTP transaction ID of the action, if applicable.
  pub target_http_transaction_id: Option<Uuid>,

  /// The target item ID of the action, if applicable.
  pub target_item_id: Option<Uuid>,

  /// The target milestone ID of the action, if applicable.
  pub target_milestone_id: Option<Uuid>,

  /// The target project ID of the action, if applicable.
  pub target_project_id: Option<Uuid>,

  /// The target role ID of the action, if applicable.
  pub target_role_id: Option<Uuid>,

  /// The target role membership ID of the action, if applicable.
  pub target_role_membership_id: Option<Uuid>,

  /// The target server log entry ID of the action, if applicable.
  pub target_server_log_entry_id: Option<Uuid>,

  /// The target session ID of the action, if applicable.
  pub target_session_id: Option<Uuid>,

  /// The target user ID of the action, if applicable.
  pub target_user_id: Option<Uuid>,

  /// The target workspace ID of the action, if applicable.
  pub target_workspace_id: Option<Uuid>,

  /// The reason why the action was performed, if applicable.
  pub reason: Option<String>

}

#[derive(Debug, Default)]
pub struct InitialActionLogEntryProperties {

  /// The ID of the action.
  pub action_id: Uuid,

  /// The ID of the HTTP transaction related to the action log entry, if applicable.
  pub http_transaction_id: Option<Uuid>,

  /// The type of actor that performed the action.
  pub actor_type: ActionLogEntryActorType,

  /// The ID of the user actor that performed the action, if applicable.
  pub actor_user_id: Option<Uuid>,

  /// The ID of the app actor that performed the action, if applicable.
  pub actor_app_id: Option<Uuid>,

  /// The type of the target resource of the action.
  pub target_resource_type: ActionLogEntryTargetResourceType,

  /// The target access policy ID of the action, if applicable.
  pub target_access_policy_id: Option<Uuid>,

  /// The target action ID of the action, if applicable.
  pub target_action_id: Option<Uuid>,

  /// The target action log entry ID of the action, if applicable.
  pub target_action_log_entry_id: Option<Uuid>,

  /// The target app ID of the action, if applicable.
  pub target_app_id: Option<Uuid>,

  /// The target app authorization ID of the action, if applicable.
  pub target_app_authorization_id: Option<Uuid>,

  /// The target app authorization credential ID of the action, if applicable.
  pub target_app_authorization_credential_id: Option<Uuid>,

  /// The target app credential ID of the action, if applicable.
  pub target_app_credential_id: Option<Uuid>,

  /// The target group ID of the action, if applicable.
  pub target_group_id: Option<Uuid>,

  /// The target group membership ID of the action, if applicable.
  pub target_group_membership_id: Option<Uuid>,

  /// The target HTTP transaction ID of the action, if applicable.
  pub target_http_transaction_id: Option<Uuid>,

  /// The target item ID of the action, if applicable.
  pub target_item_id: Option<Uuid>,

  /// The target milestone ID of the action, if applicable.
  pub target_milestone_id: Option<Uuid>,

  /// The target project ID of the action, if applicable.
  pub target_project_id: Option<Uuid>,

  /// The target role ID of the action, if applicable.
  pub target_role_id: Option<Uuid>,

  /// The target role membership ID of the action, if applicable.
  pub target_role_membership_id: Option<Uuid>,

  /// The target server log entry ID of the action, if applicable.
  pub target_server_log_entry_id: Option<Uuid>,

  /// The target session ID of the action, if applicable.
  pub target_session_id: Option<Uuid>,

  /// The target user ID of the action, if applicable.
  pub target_user_id: Option<Uuid>,

  /// The target workspace ID of the action, if applicable.
  pub target_workspace_id: Option<Uuid>,

  /// The reason why the action was performed, if applicable.
  pub reason: Option<String>

}

impl ActionLogEntry {

  /// Gets an action log entry by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/action_log_entries/get_action_log_entry_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("Action log entry with ID \"{}\" not found.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let action_log_entry = Self::convert_from_row(&row);

    return Ok(action_log_entry);

  }

  /// Converts a row into an action log entry.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return ActionLogEntry {
      id: row.get("id"),
      action_id: row.get("action_id"),
      http_transaction_id: row.get("http_transaction_id"),
      actor_type: row.get("actor_type"),
      actor_user_id: row.get("actor_user_id"),
      actor_app_id: row.get("actor_app_id"),
      target_resource_type: row.get("target_resource_type"),
      target_access_policy_id: row.get("target_access_policy_id"),
      target_action_id: row.get("target_action_id"),
      target_action_log_entry_id: row.get("target_action_log_entry_id"),
      target_app_id: row.get("target_app_id"),
      target_app_authorization_id: row.get("target_app_authorization_id"),
      target_app_authorization_credential_id: row.get("target_app_authorization_credential_id"),
      target_app_credential_id: row.get("target_app_credential_id"),
      target_group_id: row.get("target_group_id"),
      target_group_membership_id: row.get("target_group_membership_id"),
      target_http_transaction_id: row.get("target_http_transaction_id"),
      target_item_id: row.get("target_item_id"),
      target_milestone_id: row.get("target_milestone_id"),
      target_project_id: row.get("target_project_id"),
      target_role_id: row.get("target_role_id"),
      target_role_membership_id: row.get("target_role_membership_id"),
      target_server_log_entry_id: row.get("target_server_log_entry_id"),
      target_session_id: row.get("target_session_id"),
      target_user_id: row.get("target_user_id"),
      target_workspace_id: row.get("target_workspace_id"),
      reason: row.get("reason")
    };

  }

  /// Counts the number of action log entries based on a query.
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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "ActionLogEntry", "action_log_entries", "slashstep.actionLogEntries.get", true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let database_client = database_pool.get().await?;
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new action log entry.
  pub async fn create(initial_properties: &InitialActionLogEntryProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/action_log_entries/insert_action_log_entry_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.action_id,
      &initial_properties.http_transaction_id,
      &initial_properties.actor_type,
      &initial_properties.actor_user_id,
      &initial_properties.actor_app_id,
      &initial_properties.target_resource_type,
      &initial_properties.target_access_policy_id,
      &initial_properties.target_action_id,
      &initial_properties.target_action_log_entry_id,
      &initial_properties.target_app_id,
      &initial_properties.target_app_authorization_id,
      &initial_properties.target_app_authorization_credential_id,
      &initial_properties.target_app_credential_id,
      &initial_properties.target_group_id,
      &initial_properties.target_group_membership_id,
      &initial_properties.target_http_transaction_id,
      &initial_properties.target_item_id,
      &initial_properties.target_milestone_id,
      &initial_properties.target_project_id,
      &initial_properties.target_role_id,
      &initial_properties.target_role_membership_id,
      &initial_properties.target_server_log_entry_id,
      &initial_properties.target_session_id,
      &initial_properties.target_user_id,
      &initial_properties.target_workspace_id,
      &initial_properties.reason
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| ResourceError::PostgresError(error))?;

    let action_log_entry = ActionLogEntry::convert_from_row(&row);

    return Ok(action_log_entry);

  }
  
  /// Initializes the action_log_entries table.
  pub async fn initialize_action_log_entries_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/action_log_entries/initialize_action_log_entries_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Returns a list of action log entries based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ACTION_LOG_ENTRY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_ACTION_LOG_ENTRY_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "ActionLogEntry", "action_log_entries", "slashstep.actionLogEntries.get", false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let actions = rows.iter().map(ActionLogEntry::convert_from_row).collect();
    return Ok(actions);

  }

  /// Parses a string into a parameter for a slashstepql query.
  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    return Ok(Box::new(value));

  }

}

impl DeletableResource for ActionLogEntry {

  /// Deletes this action log entry.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/action_log_entries/delete_action_log_entry_row.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}

#[cfg(test)]
mod tests;