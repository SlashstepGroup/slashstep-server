#![warn(clippy::unwrap_used)]

pub mod resources;
pub mod utilities;
pub mod middleware;
pub mod routes;
pub mod predefinitions;
#[cfg(test)]
pub mod tests;

pub const DEFAULT_APP_PORT: i16 = 8080;
pub const DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT: u32 = 5;

use std::{fmt};
use axum::{body::Body, response::{IntoResponse, Response}};
use axum_extra::response::ErasedJson;
use reqwest::{StatusCode};
use serde::Serialize;
use colored::Colorize;
use thiserror::Error;
use crate::{
  resources::{
    ResourceError, access_policy::AccessPolicy, action::Action, action_log_entry::ActionLogEntry, app::App, app_authorization::AppAuthorization, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, configuration::{Configuration, EditableConfigurationProperties}, delegation_policy::DelegationPolicy, field::Field, field_choice::FieldChoice, field_value::FieldValue, group::Group, http_transaction::HTTPTransaction, item::Item, item_connection::ItemConnection, item_connection_type::ItemConnectionType, item_type::ItemType, item_type_icon::ItemTypeIcon, iteration::Iteration, membership::{InitialMembershipProperties, Membership, MembershipParentResourceType, MembershipPrincipalType}, membership_invitation::MembershipInvitation, milestone::Milestone, oauth_authorization::OAuthAuthorization, password_reset_authorization::PasswordResetAuthorization, project::Project, role::{PredefinedRoleType, Role, RoleParentResourceType}, server_log_entry::ServerLogEntry, session::Session, status::Status, user::{InitialUserProperties, User}, view::View, view_field::ViewField, webhook::Webhook, workspace::Workspace
  }
};

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
  RedisCreatePoolError(#[from] deadpool_redis::CreatePoolError),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  LocalIPAddressError(#[from] local_ip_address::Error)

}

pub async fn initialize_required_tables(database_pool: &deadpool_postgres::Pool) -> Result<(), SlashstepServerError> {

  let create_general_types_query = include_str!("./queries/create_general_types.sql");
  database_pool.get().await?.execute(create_general_types_query, &[]).await?;

  // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
  HTTPTransaction::initialize_resource_table(database_pool).await?;
  ServerLogEntry::initialize_resource_table(database_pool).await?;
  Workspace::initialize_resource_table(database_pool).await?;
  User::initialize_resource_table(database_pool).await?;
  PasswordResetAuthorization::initialize_resource_table(database_pool).await?;
  Session::initialize_resource_table(database_pool).await?;
  Group::initialize_resource_table(database_pool).await?;
  App::initialize_resource_table(database_pool).await?;
  Project::initialize_resource_table(database_pool).await?;
  Status::initialize_resource_table(database_pool).await?;
  Webhook::initialize_resource_table(database_pool).await?;
  ItemTypeIcon::initialize_resource_table(database_pool).await?;
  Iteration::initialize_resource_table(database_pool).await?;
  ItemType::initialize_resource_table(database_pool).await?;
  View::initialize_resource_table(database_pool).await?;
  Role::initialize_resource_table(database_pool).await?;
  Membership::initialize_resource_table(database_pool).await?;
  MembershipInvitation::initialize_resource_table(database_pool).await?;
  Item::initialize_resource_table(database_pool).await?;
  ItemConnectionType::initialize_resource_table(database_pool).await?;
  ItemConnection::initialize_resource_table(database_pool).await?;
  Action::initialize_resource_table(database_pool).await?;
  AppCredential::initialize_resource_table(database_pool).await?;
  Milestone::initialize_resource_table(database_pool).await?;
  ActionLogEntry::initialize_resource_table(database_pool).await?;
  OAuthAuthorization::initialize_resource_table(database_pool).await?;
  AppAuthorization::initialize_resource_table(database_pool).await?;
  AppAuthorizationCredential::initialize_resource_table(database_pool).await?;
  Field::initialize_resource_table(database_pool).await?;
  FieldChoice::initialize_resource_table(database_pool).await?;
  FieldValue::initialize_resource_table(database_pool).await?;
  ViewField::initialize_resource_table(database_pool).await?;
  Configuration::initialize_resource_table(database_pool).await?;
  DelegationPolicy::initialize_resource_table(database_pool).await?;
  AccessPolicy::initialize_resource_table(database_pool).await?;

  let database_client = database_pool.get().await?;
  let query = include_str!("./queries/items/initialize_searchable_items_view.sql");
  database_client.execute(query, &[]).await?;

  println!("{}", "Successfully initialized all tables.".blue());

  return Ok(());

}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HTTPError {
  GoneError(Option<String>),
  Forbidden(Option<String>),
  NotFoundError(Option<String>),
  ConflictError(Option<String>),
  BadRequest(Option<String>),
  UnsupportedMediaType(Option<String>),
  NotImplementedError(Option<String>),
  InternalServerError(Option<String>),
  Unauthorized(Option<String>),
  UnprocessableEntity(Option<String>),
  PayloadTooLarge(Option<String>)
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
      HTTPError::Forbidden(message) => write!(f, "{}", message.to_owned().unwrap_or("Forbidden.".to_string())),
      HTTPError::GoneError(message) => write!(f, "{}", message.to_owned().unwrap_or("Gone.".to_string())),
      HTTPError::BadRequest(message) => write!(f, "{}", message.to_owned().unwrap_or("Bad request.".to_string())),
      HTTPError::NotImplementedError(message) => write!(f, "{}", message.to_owned().unwrap_or("Not implemented.".to_string())),
      HTTPError::InternalServerError(message) => write!(f, "{}", message.to_owned().unwrap_or("Internal server error.".to_string())),
      HTTPError::Unauthorized(message) => write!(f, "{}", message.to_owned().unwrap_or("Unauthorized.".to_string())),
      HTTPError::UnsupportedMediaType(message) => write!(f, "{}", message.to_owned().unwrap_or("Unsupported media type.".to_string())),
      HTTPError::UnprocessableEntity(message) => write!(f, "{}", message.to_owned().unwrap_or("Unprocessable entity.".to_string())),
      HTTPError::PayloadTooLarge(message) => write!(f, "{}", message.to_owned().unwrap_or("Payload too large.".to_string()))
    }
  }
  
}

impl IntoResponse for HTTPError {

  fn into_response(self) -> Response {

    let (status_code, error_message) = match self {

      HTTPError::GoneError(message) => (StatusCode::GONE, message.unwrap_or("Gone.".to_string())),

      HTTPError::NotFoundError(message) => (StatusCode::NOT_FOUND, message.unwrap_or("Not found.".to_string())),

      HTTPError::Forbidden(message) => (StatusCode::FORBIDDEN, message.unwrap_or("Forbidden.".to_string())),

      HTTPError::BadRequest(message) => (StatusCode::BAD_REQUEST, message.unwrap_or("Bad request.".to_string())),

      HTTPError::ConflictError(message) => (StatusCode::CONFLICT, message.unwrap_or("Conflict.".to_string())),

      HTTPError::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message.unwrap_or("Unauthorized.".to_string())),

      HTTPError::UnsupportedMediaType(message) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, message.unwrap_or("Unsupported media type.".to_string())),

      HTTPError::NotImplementedError(message) => (StatusCode::NOT_IMPLEMENTED, message.unwrap_or("Not implemented.".to_string())),

      HTTPError::UnprocessableEntity(message) => (StatusCode::UNPROCESSABLE_ENTITY, message.unwrap_or("Unprocessable entity.".to_string())),

      HTTPError::PayloadTooLarge(message) => (StatusCode::PAYLOAD_TOO_LARGE, message.unwrap_or("Payload too large.".to_string())),

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
  pub redis_pool: deadpool_redis::Pool
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

pub fn get_environment_variable(variable_name: &str) -> Result<String, SlashstepServerError> {

  println!("Getting environment variable {}...", variable_name);
  let variable_value = match std::env::var(variable_name) {

    Ok(variable_value) => variable_value,

    Err(_) => return Err(SlashstepServerError::EnvironmentVariableNotSet(variable_name.to_string()))

  };

  return Ok(variable_value);

}

pub fn import_env_file() {

  if dotenvy::dotenv().is_ok() {

    println!("{}", "Successfully imported environment variables from .env file.".blue());

  }

}

pub async fn setup_admin_user_if_necessary(postgres_pool: &deadpool_postgres::Pool) -> Result<(), SlashstepServerError> {

  let postgres_pool = postgres_pool.clone();
  let should_setup_admin_user_configuration = Configuration::get_by_name("users.shouldSetupAdminUser", &postgres_pool).await?;
  if !should_setup_admin_user_configuration.boolean_value.unwrap_or(true) {

    return Ok(());

  }

  let mut slashstep_admin_username = get_environment_variable("SLASHSTEP_ADMIN_USERNAME").unwrap_or("".to_string());
  let mut slashstep_admin_password = match get_environment_variable("SLASHSTEP_ADMIN_PASSWORD_FILE_PATH") {

    Ok(slashstep_admin_password_file_path) => {

      let slashstep_admin_password = std::fs::read_to_string(&slashstep_admin_password_file_path)?;
      slashstep_admin_password

    }

    Err(error) => match error {

      SlashstepServerError::EnvironmentVariableNotSet(_) => "".to_string(),

      _ => return Err(error)

    }

  };

  println!("\nIt looks like this is your first time running the Slashstep Server, so let's set up an admin user.");
  println!("If you can't use the console, please set SLASHSTEP_ADMIN_USERNAME and SLASHSTEP_ADMIN_PASSWORD_FILE_PATH environment variables and restart the server. After creating the admin user, you can remove those environment variables if you want.");
  println!("\nWhat username should the admin user have?");
  loop {

    if slashstep_admin_username.is_empty() {
      
      while slashstep_admin_username.is_empty() {

        std::io::stdin().read_line(&mut slashstep_admin_username)?;

        if slashstep_admin_username.trim().is_empty() {

          println!("{}", "Username cannot be empty. Please enter a valid username.".red());
          slashstep_admin_username = "".to_string();

        }

      }

    } else {

      println!("{}", "(pre-filled from SLASHSTEP_ADMIN_USERNAME environment variable)".dimmed());

    }

    slashstep_admin_username = slashstep_admin_username.trim().to_string();

    println!("What password should the admin user have?");
    if slashstep_admin_password.is_empty() {
      
      while slashstep_admin_password.is_empty() {

        slashstep_admin_password = match rpassword::read_password() {

          Ok(password) => {

            if password.trim().is_empty() {

              println!("{}", "Password cannot be empty. Please enter a valid password.".red());
              continue;

            } else {

              password.trim().to_string()

            }

          },
          Err(error) => panic!("An error occurred while trying to read the password: {}", error)

        };

        println!("Please re-enter the password to confirm.");
        let confirmation_password = match rpassword::read_password() {

          Ok(confirmation_password) => confirmation_password.trim().to_string(),
          Err(error) => panic!("An error occurred while trying to read the password confirmation: {}", error)

        };

        if slashstep_admin_password != confirmation_password {

          println!("{}", "The passwords do not match.".red());
          println!("Let's try again. What password should the admin user have?");
          slashstep_admin_password = "".to_string();

        }

      }

    } else {

      println!("{}", "(pre-filled from file set in the SLASHSTEP_ADMIN_PASSWORD_FILE_PATH environment variable)".dimmed());

    }

    println!("Setting up admin user...");
    let admin_user = match User::create(&InitialUserProperties {
      username: Some(slashstep_admin_username.clone()),
      display_name: Some(slashstep_admin_username.clone()),
      hashed_password: Some(User::hash_password(&slashstep_admin_password)?),
      ..Default::default()
    }, &postgres_pool).await {

      Ok(admin_user) => admin_user,

      Err(error) => match error {

        ResourceError::ConflictError(_) => {

          println!("{}", "A user with that username already exists. Please choose a different username.".red());
          slashstep_admin_username = "".to_string();
          slashstep_admin_password = "".to_string();
          continue;

        },

        error => return Err(SlashstepServerError::ResourceError(error))

      }

    };

    let server_admin_role = Role::get_by_predefined_role_type(&RoleParentResourceType::Server, None, &PredefinedRoleType::ServerAdmins, &postgres_pool).await?;

    Membership::create(&InitialMembershipProperties {
      parent_resource_type: MembershipParentResourceType::Role,
      parent_role_id: Some(server_admin_role.id),
      principal_type: MembershipPrincipalType::User,
      principal_user_id: Some(admin_user.id),
      ..Default::default()
    }, &postgres_pool).await?;

    println!("{}", "All done! The admin user has been set up, and you can use it to sign in using a Slashstep client.".blue());
    println!("Thanks for using Slashstep Server. ✌️\n");

    should_setup_admin_user_configuration.update(&EditableConfigurationProperties {
      boolean_value: Some(false),
      ..Default::default()
    }, &postgres_pool).await?;

    break;

  }

  return Ok(());

}
