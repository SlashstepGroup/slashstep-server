#![warn(clippy::unwrap_used)]

pub mod resources;
pub mod errors;
pub mod utilities;
pub mod middleware;
mod routes;

#[cfg(test)]
mod tests;

use std::fmt;
use anyhow::{Result, bail};
use axum::{Json, response::{IntoResponse, Response}};
use deadpool_postgres::{Pool, tokio_postgres};
use local_ip_address::local_ip;
use postgres::NoTls;
use reqwest::StatusCode;
use tokio::net::TcpListener;
use colored::Colorize;

use crate::resources::{access_policy::AccessPolicy, action::Action, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, group::Group, http_request::HTTPRequest, item::Item, milestone::Milestone, project::Project, role::Role, user::User, workspace::Workspace};

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

pub async fn initialize_required_tables(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

  // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
  HTTPRequest::initialize_http_requests_table(postgres_client).await?;
  User::initialize_users_table(postgres_client).await?;
  Group::initialize_groups_table(postgres_client).await?;
  App::initialize_apps_table(postgres_client).await?;
  Workspace::initialize_workspaces_table(postgres_client).await?;
  Project::initialize_projects_table(postgres_client).await?;
  Role::initialize_roles_table(postgres_client).await?;
  Item::initialize_items_table(postgres_client).await?;
  Action::initialize_actions_table(postgres_client).await?;
  AppCredential::initialize_app_credentials_table(postgres_client).await?;
  AppAuthorization::initialize_app_authorizations_table(postgres_client).await?;
  AppAuthorizationCredential::initialize_app_authorization_credentials_table(postgres_client).await?;
  Milestone::initialize_milestones_table(postgres_client).await?;
  AccessPolicy::initialize_access_policies_table(postgres_client).await?;
  
  return Ok(());

}

#[derive(Debug, Clone)]
pub enum HTTPError {
  NotFoundError(Option<String>),
  ConflictError(Option<String>),
  BadRequestError(Option<String>),
  InternalServerError(Option<String>)
}

impl fmt::Display for HTTPError {

  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      HTTPError::NotFoundError(message) => write!(f, "{}", message.to_owned().unwrap_or("Not found.".to_string())),
      HTTPError::ConflictError(message) => write!(f, "{}", message.to_owned().unwrap_or("Conflict.".to_string())),
      HTTPError::BadRequestError(message) => write!(f, "{}", message.to_owned().unwrap_or("Bad request.".to_string())),
      HTTPError::InternalServerError(message) => write!(f, "{}", message.to_owned().unwrap_or("Internal server error.".to_string()))
    }
  }
  
}

impl IntoResponse for HTTPError {
  fn into_response(self) -> Response {
    let (status_code, error_message) = match self {

      HTTPError::NotFoundError(message) => (StatusCode::NOT_FOUND, message.unwrap_or("Not found.".to_string())),

      HTTPError::BadRequestError(message) => (StatusCode::BAD_REQUEST, message.unwrap_or("Bad request.".to_string())),

      HTTPError::ConflictError(message) => (StatusCode::CONFLICT, message.unwrap_or("Conflict.".to_string())),

      HTTPError::InternalServerError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Something bad happened on our side. Please try again later.".to_string())

    };

    return (status_code, Json(serde_json::json!({"message": error_message}))).into_response();

  }
}

#[derive(Clone)]
pub struct AppState {
  pub database_pool: deadpool_postgres::Pool,
}

#[derive(Clone)]
pub struct RequestData {
  pub http_request: HTTPRequest
}

fn get_environment_variable(variable_name: &str) -> Result<String> {

  let variable_value = match std::env::var(variable_name) {
    Ok(variable_value) => variable_value,
    Err(_) => bail!("Please set a {} environment variable.", variable_name)
  };

  return Ok(variable_value);

}

async fn create_database_pool() -> Result<deadpool_postgres::Pool> {

  let host = get_environment_variable("POSTGRESQL_HOST")?;
  let username = get_environment_variable("POSTGRESQL_USERNAME")?;
  let database_name = get_environment_variable("POSTGRESQL_DATABASE_NAME")?;

  let mut postgres_config = tokio_postgres::Config::new();
  postgres_config.host(host);
  postgres_config.user(username);
  postgres_config.dbname(database_name);
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

#[tokio::main]
async fn main() -> Result<()> {

  println!("Slashstep Server v{}", env!("CARGO_PKG_VERSION"));

  if dotenvy::dotenv().is_ok() {

    println!("{}", "Successfully imported environment variables from .env file.".blue());

  }

  let pool = create_database_pool().await?;
  let state = AppState {
    database_pool: pool,
  };

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