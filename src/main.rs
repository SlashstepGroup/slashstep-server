#![warn(clippy::unwrap_used)]

pub mod resources;
pub mod utilities;
pub mod middleware;
mod routes;
mod pre_definitions;

#[cfg(test)]
mod tests;

use std::{fmt, sync::Arc};
use axum::{body::Body, response::{IntoResponse, Response}};
use axum_extra::response::ErasedJson;
use deadpool_postgres::{Pool, tokio_postgres};
use local_ip_address::local_ip;
use postgres::NoTls;
use reqwest::{StatusCode};
use serde::Serialize;
use tokio::net::TcpListener;
use colored::Colorize;
use uuid::Uuid;
use thiserror::Error;

use crate::{pre_definitions::{initialize_pre_defined_actions, initialize_pre_defined_roles}, resources::{access_policy::{AccessPolicy, AccessPolicyError}, action::{Action, ActionError}, action_log_entry::{ActionLogEntry, ActionLogEntryError}, app::{App, AppError}, app_authorization::{AppAuthorization, AppAuthorizationError}, app_authorization_credential::{AppAuthorizationCredential, AppAuthorizationCredentialError}, app_credential::{AppCredential, AppCredentialError}, group::{Group, GroupError}, group_membership::{GroupMembership, GroupMembershipError}, http_transaction::{HTTPTransaction, HTTPTransactionError}, item::{Item, ItemError}, milestone::{Milestone, MilestoneError}, project::{Project, ProjectError}, role::{Role, RoleError}, role_memberships::{RoleMembership, RoleMembershipError}, server_log_entry::{ServerLogEntry, ServerLogEntryError}, session::{Session, SessionError}, user::{User, UserError}, workspace::{Workspace, WorkspaceError}}};

const DEFAULT_APP_PORT: i16 = 8080;
const DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT: u32 = 5;

fn print_shutdown_message() {

  println!("{}", "Slashstep Server is shutting down...".blue());

}

async fn gracefully_shutdown() {

  let ctrl_c = async {
    tokio::signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
      .expect("failed to install signal handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
    _ = ctrl_c => {
      
      print_shutdown_message();

    },
    _ = terminate => {

      print_shutdown_message();

    },
  }

}

fn get_app_port_string() -> String {

  match std::env::var("APP_PORT") {
    Ok(app_port) => app_port,
    Err(_) => {
      println!("{}", format!("Please set an APP_PORT environment variable. Defaulting to {}.", DEFAULT_APP_PORT).yellow());
      DEFAULT_APP_PORT.to_string()
    }
  }

}

#[derive(Debug, Error)]
pub enum SlashstepServerError {
  #[error("Please set a value for the environment variable \"{0}\".")]
  EnvironmentVariableNotSet(String),

  #[error(transparent)]
  HTTPTransactionError(#[from] HTTPTransactionError),

  #[error(transparent)]
  UserError(#[from] UserError),

  #[error(transparent)]
  SessionError(#[from] SessionError),

  #[error(transparent)]
  GroupError(#[from] GroupError),

  #[error(transparent)]
  GroupMembershipError(#[from] GroupMembershipError),

  #[error(transparent)]
  AppError(#[from] AppError),

  #[error(transparent)]
  WorkspaceError(#[from] WorkspaceError),

  #[error(transparent)]
  ProjectError(#[from] ProjectError),

  #[error(transparent)]
  RoleError(#[from] RoleError),

  #[error(transparent)]
  ItemError(#[from] ItemError),

  #[error(transparent)]
  ActionError(#[from] ActionError),

  #[error(transparent)]
  ActionLogEntryError(#[from] ActionLogEntryError),

  #[error(transparent)]
  AppAuthorizationError(#[from] AppAuthorizationError),

  #[error(transparent)]
  ServerLogEntryError(#[from] ServerLogEntryError),

  #[error(transparent)]
  AppAuthorizationCredentialError(#[from] AppAuthorizationCredentialError),

  #[error(transparent)]
  AppCredentialError(#[from] AppCredentialError),

  #[error(transparent)]
  MilestoneError(#[from] MilestoneError),

  #[error(transparent)]
  AccessPolicyError(#[from] AccessPolicyError),

  #[error(transparent)]
  RoleMembershipError(#[from] RoleMembershipError),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  ParseIntError(#[from] std::num::ParseIntError),

  #[error(transparent)]
  DeadpoolBuildError(#[from] deadpool_postgres::BuildError),

  #[error(transparent)]
  DeadpoolPoolError(#[from] deadpool_postgres::PoolError),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  LocalIPAddressError(#[from] local_ip_address::Error),

  #[error(transparent)]
  AnyhowError(#[from] anyhow::Error)

}

pub async fn initialize_required_tables(postgres_client: &mut deadpool_postgres::Client) -> Result<(), SlashstepServerError> {

  // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
  HTTPTransaction::initialize_http_transactions_table(postgres_client).await?;
  ServerLogEntry::initialize_server_log_entries_table(postgres_client).await?;
  User::initialize_users_table(postgres_client).await?;
  Session::initialize_sessions_table(postgres_client).await?;
  Group::initialize_groups_table(postgres_client).await?;
  App::initialize_apps_table(postgres_client).await?;
  GroupMembership::initialize_app_authorizations_table(postgres_client).await?;
  Workspace::initialize_workspaces_table(postgres_client).await?;
  Project::initialize_projects_table(postgres_client).await?;
  Role::initialize_roles_table(postgres_client).await?;
  RoleMembership::initialize_role_memberships_table(postgres_client).await?;
  Item::initialize_items_table(postgres_client).await?;
  Action::initialize_actions_table(postgres_client).await?;
  AppCredential::initialize_app_credentials_table(postgres_client).await?;
  AppAuthorization::initialize_app_authorizations_table(postgres_client).await?;
  AppAuthorizationCredential::initialize_app_authorization_credentials_table(postgres_client).await?;
  Milestone::initialize_milestones_table(postgres_client).await?;
  ActionLogEntry::initialize_action_log_entries_table(postgres_client).await?;
  AccessPolicy::initialize_access_policies_table(postgres_client).await?;

  let query = include_str!("./queries/action_log_entries/add_access_policies_reference.sql");
  postgres_client.execute(query, &[]).await?;
  
  return Ok(());

}

#[derive(Debug, Clone)]
pub enum HTTPError {
  GoneError(Option<String>),
  ForbiddenError(Option<String>),
  NotFoundError(Option<String>),
  ConflictError(Option<String>),
  BadRequestError(Option<String>),
  NotImplementedError(Option<String>),
  InternalServerError(Option<String>),
  UnauthorizedError(Option<String>),
  UnprocessableEntity(Option<String>)
}

#[derive(Debug, Serialize)]
pub struct HTTPErrorBody {
  pub message: String
}

impl fmt::Display for HTTPError {

  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      HTTPError::NotFoundError(message) => write!(f, "{}", message.to_owned().unwrap_or("Not found.".to_string())),
      HTTPError::ConflictError(message) => write!(f, "{}", message.to_owned().unwrap_or("Conflict.".to_string())),
      HTTPError::ForbiddenError(message) => write!(f, "{}", message.to_owned().unwrap_or("Forbidden.".to_string())),
      HTTPError::GoneError(message) => write!(f, "{}", message.to_owned().unwrap_or("Gone.".to_string())),
      HTTPError::BadRequestError(message) => write!(f, "{}", message.to_owned().unwrap_or("Bad request.".to_string())),
      HTTPError::NotImplementedError(message) => write!(f, "{}", message.to_owned().unwrap_or("Not implemented.".to_string())),
      HTTPError::InternalServerError(message) => write!(f, "{}", message.to_owned().unwrap_or("Internal server error.".to_string())),
      HTTPError::UnauthorizedError(message) => write!(f, "{}", message.to_owned().unwrap_or("Unauthorized.".to_string())),
      HTTPError::UnprocessableEntity(message) => write!(f, "{}", message.to_owned().unwrap_or("Unprocessable entity.".to_string()))
    }
  }
  
}

impl IntoResponse for HTTPError {
  fn into_response(self) -> Response {
    let (status_code, error_message) = match self {

      HTTPError::GoneError(message) => (StatusCode::GONE, message.unwrap_or("Gone.".to_string())),

      HTTPError::NotFoundError(message) => (StatusCode::NOT_FOUND, message.unwrap_or("Not found.".to_string())),

      HTTPError::ForbiddenError(message) => (StatusCode::FORBIDDEN, message.unwrap_or("Forbidden.".to_string())),

      HTTPError::BadRequestError(message) => (StatusCode::BAD_REQUEST, message.unwrap_or("Bad request.".to_string())),

      HTTPError::ConflictError(message) => (StatusCode::CONFLICT, message.unwrap_or("Conflict.".to_string())),

      HTTPError::UnauthorizedError(message) => (StatusCode::UNAUTHORIZED, message.unwrap_or("Unauthorized.".to_string())),

      HTTPError::NotImplementedError(message) => (StatusCode::NOT_IMPLEMENTED, message.unwrap_or("Not implemented.".to_string())),

      HTTPError::UnprocessableEntity(message) => (StatusCode::UNPROCESSABLE_ENTITY, message.unwrap_or("Unprocessable entity.".to_string())),

      HTTPError::InternalServerError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Something bad happened on our side. Please try again later.".to_string()),

    };

    return (status_code, ErasedJson::pretty(HTTPErrorBody {
      message: error_message
    })).into_response();

  }
}

impl HTTPError {

  pub async fn print_and_save(&self, http_request_id: Option<&Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<Result<ServerLogEntry, ServerLogEntryError>, ()> {

    let server_log_entry = ServerLogEntry::from_http_error(self, http_request_id, postgres_client).await;
    return Ok(server_log_entry);

  }

}

#[derive(Debug, Clone)]
pub struct AppState {
  pub database_pool: Arc<deadpool_postgres::Pool>,
}

pub fn handle_pool_error(error: deadpool_postgres::PoolError) -> Response<Body> {

  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  return http_error.into_response();

}

fn get_environment_variable(variable_name: &str) -> Result<String, SlashstepServerError> {

  let variable_value = match std::env::var(variable_name) {
    Ok(variable_value) => variable_value,
    Err(_) => return Err(SlashstepServerError::EnvironmentVariableNotSet(variable_name.to_string()))
  };

  return Ok(variable_value);

}

async fn create_database_pool() -> Result<deadpool_postgres::Pool, SlashstepServerError> {

  let host = get_environment_variable("POSTGRESQL_HOST")?;
  let username = get_environment_variable("POSTGRESQL_USERNAME")?;
  let database_name = get_environment_variable("POSTGRESQL_DATABASE_NAME")?;
  let password_path = get_environment_variable("POSTGRESQL_PASSWORD_PATH")?;
  let password = std::fs::read_to_string(password_path)?;

  let mut postgres_config = tokio_postgres::Config::new();
  postgres_config.host(host);
  postgres_config.user(username);
  postgres_config.dbname(database_name);
  postgres_config.password(password);
  let manager_config = deadpool_postgres::ManagerConfig {
    recycling_method: deadpool_postgres::RecyclingMethod::Fast
  };
  let manager = deadpool_postgres::Manager::from_config(postgres_config, NoTls, manager_config);

  let maximum_postgres_connection_count_string = match get_environment_variable("MAXIMUM_POSTGRES_CONNECTION_COUNT") {

    Ok(maximum_postgres_connection_count) => maximum_postgres_connection_count,
    Err(_) => {

      println!("{}", format!("Please set a MAXIMUM_POSTGRES_CONNECTION_COUNT environment variable. Defaulting to {}.", DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT).yellow());
      DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT.to_string()

    }

  };
  let maximum_postgres_connection_count = maximum_postgres_connection_count_string.parse::<usize>()?;

  let pool = Pool::builder(manager).max_size(maximum_postgres_connection_count).build()?;
  return Ok(pool);

}

pub fn import_env_file() {

  if dotenvy::dotenv().is_ok() {

    println!("{}", "Successfully imported environment variables from .env file.".blue());

  }

}

#[tokio::main]
async fn main() -> Result<(), SlashstepServerError> {

  println!("Slashstep Server v{}", env!("CARGO_PKG_VERSION"));

  import_env_file();
  let pool = create_database_pool().await?;
  let state = AppState {
    database_pool: Arc::new(pool),
  };

  let mut postgres_client = state.database_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  initialize_pre_defined_actions(&mut postgres_client).await?;
  initialize_pre_defined_roles(&mut postgres_client).await?;
  drop(postgres_client); // Drop the client to release the connection back to the pool. For some reason, this doesn't happen automatically.

  let app_port = get_app_port_string();
  let router = routes::get_router(state.clone()).with_state(state);
  let listener = TcpListener::bind(format!("0.0.0.0:{}", app_port)).await?;
  let app_ip = local_ip()?;
  println!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at http://localhost:{}, or your local network at http://{}:{}.", app_port, app_port, app_ip, app_port).green());
  axum::serve(listener, router)
    .with_graceful_shutdown(gracefully_shutdown())
    .await?;

  return Ok(());

}