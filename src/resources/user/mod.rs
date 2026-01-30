/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use std::net::IpAddr;
use postgres::error::SqlState;
use postgres_types::ToSql;
use uuid::Uuid;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UserError {
  #[error("A user with the {0} \"{1}\" does not exist.")]
  NotFoundError(String, String),

  #[error("A user with the username \"{0}\" already exists.")]
  ConflictError(String),

  #[error("A user with the ID \"{0}\" does not have the required permissions to perform the action \"{1}\".")]
  ForbiddenError(String, String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

#[derive(Debug, Clone)]
pub struct User {

  /// The user's ID.
  pub id: Uuid,

  /// The user's username, if applicable. Only non-anonymous users have a username.
  pub username: Option<String>,

  /// The user's display name, if applicable. Only non-anonymous users have a display name.
  pub display_name: Option<String>,

  /// The user's hashed password, if applicable. Only non-anonymous users have a hashed password.
  hashed_password: Option<String>,

  /// Whether the user is anonymous.
  pub is_anonymous: bool,

  /// The user's IP address, if applicable. Only anonymous users have an IP address.
  pub ip_address: Option<IpAddr>

}

pub struct InitialUserProperties {

  /// The user's username, if applicable. Only non-anonymous users have a username.
  pub username: Option<String>,

  /// The user's display name, if applicable. Only non-anonymous users have a display name.
  pub display_name: Option<String>,

  /// The user's hashed password, if applicable. Only non-anonymous users have a hashed password.
  pub hashed_password: Option<String>,

  /// Whether the user is anonymous.
  pub is_anonymous: bool,

  /// The user's IP address, if applicable. Only anonymous users have an IP address.
  pub ip_address: Option<IpAddr>

}

impl User {

  /// Creates a new user.
  pub async fn create(initial_properties: &InitialUserProperties, postgres_client: &deadpool_postgres::Client) -> Result<Self, UserError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/users/insert-user-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.username,
      &initial_properties.display_name,
      &initial_properties.hashed_password,
      &initial_properties.is_anonymous,
      &initial_properties.ip_address
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => {

          let username = match initial_properties.username.clone() {

            Some(username) => username,

            // TODO: For IP users, we should make UserError more specific.
            None => return UserError::PostgresError(error)

          };

          UserError::ConflictError(username)
          
        },
        
        _ => UserError::PostgresError(error)

      },

      None => UserError::PostgresError(error)

    })?;

    // Return the action.
    let user = User {
      id: row.get("id"),
      username: row.get("username"),
      display_name: row.get("display_name"),
      hashed_password: row.get("hashed_password"),
      is_anonymous: row.get("is_anonymous"),
      ip_address: row.get("ip_address")
    };

    return Ok(user);

  }

  pub fn from_row(row: &postgres::Row) -> Self {

    return User {
      id: row.get("id"),
      username: row.get("username"),
      display_name: row.get("display_name"),
      hashed_password: row.get("hashed_password"),
      is_anonymous: row.get("is_anonymous"),
      ip_address: row.get("ip_address")
    };

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<User, UserError> {

    let query = include_str!("../../queries/users/get-user-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(UserError::NotFoundError("ID".to_string(), id.to_string()))

      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(UserError::NotFoundError("ID".to_string(), id.to_string())),

          _ => return Err(UserError::PostgresError(error))

        },

        None => return Err(UserError::PostgresError(error))

      }

    };

    let user = User::from_row(&row);

    return Ok(user);

  }

  pub async fn get_by_ip_address(ip_address: &IpAddr, postgres_client: &deadpool_postgres::Client) -> Result<User, UserError> {

    let query = include_str!("../../queries/users/get-user-row-by-ip-address.sql");
    let row = match postgres_client.query_opt(query, &[&ip_address]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(UserError::NotFoundError("IP address".to_string(), ip_address.to_string()))

      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(UserError::NotFoundError("IP address".to_string(), ip_address.to_string())),

          _ => return Err(UserError::PostgresError(error))

        },

        None => return Err(UserError::PostgresError(error))

      }

    };

    let user = User::from_row(&row);

    return Ok(user);

  }

  /// Initializes the users table.
  pub async fn initialize_users_table(postgres_client: &deadpool_postgres::Client) -> Result<(), UserError> {

    let query = include_str!("../../queries/users/initialize-users-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub fn get_hashed_password(&self) -> &str {

    let hashed_password = self.hashed_password.as_ref().expect("User does not have a hashed password.");
    return &hashed_password;

  }

}