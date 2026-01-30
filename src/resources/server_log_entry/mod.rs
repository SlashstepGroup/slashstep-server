use core::fmt;
use postgres_types::{FromSql, ToSql};
use uuid::Uuid;
use colored::Colorize;
use crate::{HTTPError, resources::ResourceError};

#[derive(Debug, ToSql, FromSql, Copy, Clone)]
#[postgres(name = "server_log_entry_level")]
pub enum ServerLogEntryLevel {
  Success,
  Trace,
  Info,
  Warning,
  Error,
  Critical
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

#[derive(Debug)]
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

pub struct InitialServerLogEntryProperties<'a> {

  /// The message of the server log entry.
  pub message: &'a str,

  /// The HTTP request ID of the server log entry, if applicable.
  pub http_transaction_id: Option<&'a Uuid>,

  /// The level of the server log entry.
  pub level: &'a ServerLogEntryLevel

}

impl ServerLogEntry {

  pub async fn critical(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Critical;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn trace(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Trace;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn info(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Info;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn warning(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Warning;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn error(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Error;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn success(message: &str, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = &ServerLogEntryLevel::Success;
    let properties = InitialServerLogEntryProperties { message, http_transaction_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, database_pool, true).await;
    return server_log_entry_result;

  }

  pub async fn from_http_error(http_error: &HTTPError, http_transaction_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let level = match http_error {
      HTTPError::InternalServerError(_) => &ServerLogEntryLevel::Critical,
      _ => &ServerLogEntryLevel::Error
    };
    let message = &http_error.to_string();
    let properties = InitialServerLogEntryProperties {
      message,
      http_transaction_id,
      level
    };
    let server_log_entry = ServerLogEntry::create(&properties, database_pool, true).await?;
    return Ok(server_log_entry);

  }

  pub async fn initialize_server_log_entries_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/server_log_entries/initialize_server_log_entries_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub async fn create<'a>(properties: &InitialServerLogEntryProperties<'a>, database_pool: &deadpool_postgres::Pool, should_print_to_console: bool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/server_log_entries/insert-server-log-entry-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.message,
      &properties.http_transaction_id,
      &properties.level
    ];
    let database_client = database_pool.get().await?;
    let row_result = database_client.query_one(query, parameters).await;

    let row = match row_result {

      Ok(row) => row,

      Err(error) => {
        
        if should_print_to_console {

          let temporary_server_log_entry = ServerLogEntry {
            id: Uuid::now_v7(),
            message: properties.message.to_string(),
            http_transaction_id: properties.http_transaction_id.copied(),
            level: *properties.level
          };

          temporary_server_log_entry.print_to_console();

        }

        return Err(ResourceError::PostgresError(error));

      }

    };

    let server_log_entry = ServerLogEntry {
      id: row.get("id"),
      message: row.get("message"),
      http_transaction_id: row.get("http_transaction_id"),
      level: row.get("level")
    };

    if should_print_to_console {

      server_log_entry.print_to_console();

    }

    return Ok(server_log_entry);

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