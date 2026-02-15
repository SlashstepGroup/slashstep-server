#[cfg(test)]
mod tests;

use core::fmt;
use std::str::FromStr;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use colored::Colorize;
use crate::{HTTPError, resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "message",
  "http_transaction_id",
  "level"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "http_transaction_id"
];
pub const RESOURCE_NAME: &str = "ServerLogEntry";
pub const DATABASE_TABLE_NAME: &str = "server_log_entries";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.serverLogEntries.get";

#[derive(Debug, ToSql, FromSql, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[postgres(name = "server_log_entry_level")]
pub enum ServerLogEntryLevel {
  Success,
  Trace,
  Info,
  Warning,
  Error,
  Critical
}

impl FromStr for ServerLogEntryLevel {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "Success" => Ok(ServerLogEntryLevel::Success),
      "Trace" => Ok(ServerLogEntryLevel::Trace),
      "Info" => Ok(ServerLogEntryLevel::Info),
      "Warning" => Ok(ServerLogEntryLevel::Warning),
      "Error" => Ok(ServerLogEntryLevel::Error),
      "Critical" => Ok(ServerLogEntryLevel::Critical),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }
    
  }

}

impl fmt::Display for ServerLogEntryLevel {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ServerLogEntryLevel::Success => write!(f, "Success"),
      ServerLogEntryLevel::Trace => write!(f, "Trace"),
      ServerLogEntryLevel::Info => write!(f, "Info"),
      ServerLogEntryLevel::Warning => write!(f, "Warning"),
      ServerLogEntryLevel::Error => write!(f, "Error"),
      ServerLogEntryLevel::Critical => write!(f, "Critical")
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerLogEntry {
  
  /// The ID of the server log entry.
  pub id: Uuid,

  /// The message of the server log entry.
  pub message: String,

  /// The HTTP transaction ID of the server log entry, if applicable.
  pub http_transaction_id: Option<Uuid>,

  /// The level of the server log entry.
  pub level: ServerLogEntryLevel

}

pub struct InitialServerLogEntryProperties {

  /// The message of the server log entry.
  pub message: String,

  /// The HTTP transaction ID of the server log entry, if applicable.
  pub http_transaction_id: Option<Uuid>,

  /// The level of the server log entry.
  pub level: ServerLogEntryLevel

}

impl ServerLogEntry {

  /// Converts a row into a server log entry.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Self {
      id: row.get("id"),
      message: row.get("message"),
      http_transaction_id: row.get("http_transaction_id"),
      level: row.get("level")
    };

  }

  /// Counts the number of items based on a query.
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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let database_client = database_pool.get().await?;
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  pub async fn critical(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Critical;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);

  }

  pub async fn trace(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Trace;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);

  }

  pub async fn info(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Info;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);

  }

  pub async fn warning(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Warning;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);

  }

  pub async fn error(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Error;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);
  }

  pub async fn success(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Success;
    let properties = InitialServerLogEntryProperties { 
      message: message.to_string(), 
      http_transaction_id: http_transaction_id.copied(), 
      level: *level 
    };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry_result.print_to_console();
    return Ok(server_log_entry_result);

  }

  pub async fn from_http_error(http_error: &HTTPError, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = match http_error {
      HTTPError::InternalServerError(_) => &ServerLogEntryLevel::Critical,
      _ => &ServerLogEntryLevel::Error
    };
    let message = http_error.to_string();
    let properties = InitialServerLogEntryProperties {
      message: message.to_string(),
      http_transaction_id: http_transaction_id.copied(),
      level: *level
    };
    let server_log_entry = ServerLogEntry::create(&properties, database_pool).await?;
    server_log_entry.print_to_console();
    return Ok(server_log_entry);

  }

  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/server_log_entries/initialize_server_log_entries_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialServerLogEntryProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/server_log_entries/insert_server_log_entry_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.message,
      &initial_properties.http_transaction_id,
      &initial_properties.level
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the role.
    let role = Self::convert_from_row(&row);

    return Ok(role);

  }

  /// Gets a server log entry by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/server_log_entries/get_server_log_entry_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A server log entry with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  pub fn get_formatted_message(&self) -> String {

    let level_prefix = format!("[{}]", self.level);
    let request_id_prefix = match &self.http_transaction_id {

      Some(http_transaction_id) => format!("[{}] ", http_transaction_id),

      None => String::new()

    };
    let formatted_message = format!("{} {}{}", level_prefix, request_id_prefix, self.message);
    let formatted_message = match &self.level {
      ServerLogEntryLevel::Success => format!("{}", formatted_message.green()),
      ServerLogEntryLevel::Critical => format!("{}", formatted_message.on_red()),
      ServerLogEntryLevel::Error => format!("{}", formatted_message.red()),
      ServerLogEntryLevel::Warning => format!("{}", formatted_message.yellow()),
      ServerLogEntryLevel::Info => format!("{}", formatted_message.blue()),
      ServerLogEntryLevel::Trace => format!("{}", formatted_message.dimmed())
    };
    return formatted_message;
    
  }

  /// Returns a list of server log entries based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let actions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(actions);

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

        "level" => {

          let permission_level = match ServerLogEntryLevel::from_str(value) {

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

  pub fn print_to_console(&self) {

    match &self.level {

      ServerLogEntryLevel::Critical | ServerLogEntryLevel::Error => {

        eprintln!("{}", self.get_formatted_message());

      },

      _ => {

        println!("{}", self.get_formatted_message());

      }

    }

  }
  
}

impl DeletableResource for ServerLogEntry {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/server_log_entries/delete_server_log_entry_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}