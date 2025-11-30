use core::fmt;
use postgres_types::{FromSql, ToSql};
use uuid::Uuid;
use colored::Colorize;
use crate::HTTPError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerLogEntryError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

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

  /// The HTTP request ID of the server log entry, if applicable.
  pub http_request_id: Option<Uuid>,

  /// The level of the server log entry.
  pub level: ServerLogEntryLevel

}

pub struct InitialServerLogEntryProperties<'a> {

  /// The message of the server log entry.
  pub message: &'a str,

  /// The HTTP request ID of the server log entry, if applicable.
  pub http_request_id: Option<&'a Uuid>,

  /// The level of the server log entry.
  pub level: &'a ServerLogEntryLevel

}

impl ServerLogEntry {

  pub async fn critical(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Critical;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn trace(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Trace;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn info(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Info;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn warning(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Warning;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn error(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Error;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn success(message: &str, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = &ServerLogEntryLevel::Success;
    let properties = InitialServerLogEntryProperties { message, http_request_id, level };
    let server_log_entry_result = ServerLogEntry::create(&properties, postgres_client, true).await;
    return server_log_entry_result;

  }

  pub async fn from_http_error(http_error: &HTTPError, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ServerLogEntryError> {

    let level = match http_error {
      HTTPError::InternalServerError(_) => &ServerLogEntryLevel::Critical,
      _ => &ServerLogEntryLevel::Error
    };
    let message = &http_error.to_string();
    let properties = InitialServerLogEntryProperties {
      message,
      http_request_id,
      level
    };
    let server_log_entry = ServerLogEntry::create(&properties, postgres_client, true).await?;
    return Ok(server_log_entry);

  }

  pub async fn create<'a>(properties: &InitialServerLogEntryProperties<'a>, postgres_client: &mut deadpool_postgres::Client, should_print_to_console: bool) -> Result<Self, ServerLogEntryError> {

    let query = include_str!("../queries/server-log-entries/insert-server-log-entry-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.message,
      &properties.http_request_id,
      &properties.level
    ];
    let row_result = postgres_client.query_one(query, parameters).await;

    let row = match row_result {

      Ok(row) => row,

      Err(error) => {
        
        if should_print_to_console {

          let temporary_server_log_entry = ServerLogEntry {
            id: Uuid::now_v7(),
            message: properties.message.to_string(),
            http_request_id: properties.http_request_id.copied(),
            level: *properties.level
          };

          temporary_server_log_entry.print_to_console();

        }

        return Err(ServerLogEntryError::PostgresError(error));

      }

    };

    let server_log_entry = ServerLogEntry {
      id: row.get("id"),
      message: row.get("message"),
      http_request_id: row.get("http_request_id"),
      level: row.get("level")
    };

    if should_print_to_console {

      server_log_entry.print_to_console();

    }

    return Ok(server_log_entry);

  }

  pub fn get_formatted_message(&self) -> String {

    let level_prefix = format!("[{}]", self.level);
    let request_id_prefix = match &self.http_request_id {

      Some(http_request_id) => format!("[{}] ", http_request_id),

      None => String::new()

    };
    let formatted_message = format!("{} {}{}", level_prefix, request_id_prefix, self.message);
    let formatted_message = match &self.level {
      ServerLogEntryLevel::Success => format!("{}", formatted_message.green()),
      ServerLogEntryLevel::Critical => format!("{}", formatted_message.on_red()),
      ServerLogEntryLevel::Error => format!("{}", formatted_message.red()),
      ServerLogEntryLevel::Warning => format!("{}", formatted_message.yellow()),
      ServerLogEntryLevel::Info => format!("{}", formatted_message.cyan()),
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