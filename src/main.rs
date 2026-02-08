#![warn(clippy::unwrap_used)]

pub mod resources;
pub mod utilities;
pub mod middleware;
mod routes;
mod predefinitions;
#[cfg(test)]
mod tests;

use std::{fmt};
use axum::{body::Body, response::{IntoResponse, Response}};
use axum_extra::response::ErasedJson;
use deadpool_postgres::{Pool, tokio_postgres};
use local_ip_address::local_ip;
use postgres::NoTls;
use reqwest::{StatusCode};
use serde::Serialize;
use tokio::net::TcpListener;
use colored::Colorize;
use thiserror::Error;
use crate::{
  predefinitions::{
    initialize_predefined_actions, 
    initialize_predefined_roles
  }, 
  resources::{
    ResourceError, access_policy::AccessPolicy, action::Action, action_log_entry::ActionLogEntry, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, delegation_policy::DelegationPolicy, group::Group, group_membership::GroupMembership, http_transaction::HTTPTransaction, item::Item, milestone::Milestone, oauth_authorization::OAuthAuthorization, project::Project, role::Role, role_memberships::RoleMembership, server_log_entry::ServerLogEntry, session::Session, user::User, workspace::Workspace
  },
  utilities::resource_hierarchy::ResourceHierarchyError
};

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
  ResourceError(#[from] ResourceError),

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
  ResourceHierarchyError(#[from] ResourceHierarchyError)

}

pub async fn initialize_required_tables(database_pool: &deadpool_postgres::Pool) -> Result<(), SlashstepServerError> {

  // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
  HTTPTransaction::initialize_resource_table(database_pool).await?;
  ServerLogEntry::initialize_resource_table(database_pool).await?;
  User::initialize_resource_table(database_pool).await?;
  Session::initialize_resource_table(database_pool).await?;
  Group::initialize_resource_table(database_pool).await?;
  App::initialize_resource_table(database_pool).await?;
  GroupMembership::initialize_resource_table(database_pool).await?;
  Workspace::initialize_resource_table(database_pool).await?;
  Project::initialize_resource_table(database_pool).await?;
  Role::initialize_resource_table(database_pool).await?;
  RoleMembership::initialize_resource_table(database_pool).await?;
  Item::initialize_resource_table(database_pool).await?;
  Action::initialize_resource_table(database_pool).await?;
  AppCredential::initialize_resource_table(database_pool).await?;
  Milestone::initialize_resource_table(database_pool).await?;
  ActionLogEntry::initialize_resource_table(database_pool).await?;
  OAuthAuthorization::initialize_resource_table(database_pool).await?;
  AppAuthorization::initialize_resource_table(database_pool).await?;
  AppAuthorizationCredential::initialize_resource_table(database_pool).await?;
  AccessPolicy::initialize_resource_table(database_pool).await?;
  DelegationPolicy::initialize_resource_table(database_pool).await?;
  
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

  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

#[derive(Debug, Clone)]
pub struct AppState {
  pub database_pool: deadpool_postgres::Pool,
}

pub async fn get_json_web_token_public_key() -> Result<String, ResourceError> {

  let jwt_public_key_path = std::env::var("JWT_PUBLIC_KEY_PATH")?;
  let jwt_public_key = std::fs::read_to_string(&jwt_public_key_path)?;

  return Ok(jwt_public_key);

}

pub async fn get_json_web_token_private_key() -> Result<String, ResourceError> {

  let jwt_private_key_path = std::env::var("JWT_PRIVATE_KEY_PATH")?;
  let jwt_private_key = std::fs::read_to_string(&jwt_private_key_path)?;

  return Ok(jwt_private_key);

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
    database_pool: pool,
  };

  initialize_required_tables(&state.database_pool).await?;
  initialize_predefined_actions(&state.database_pool).await?;
  initialize_predefined_roles(&state.database_pool).await?;

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