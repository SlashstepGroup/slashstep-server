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

use crate::resources::ResourceError;

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
  pub async fn create(initial_properties: &InitialUserProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/users/insert-user-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.username,
      &initial_properties.display_name,
      &initial_properties.hashed_password,
      &initial_properties.is_anonymous,
      &initial_properties.ip_address
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => {

          let username = match initial_properties.username.clone() {

            Some(username) => username,

            // TODO: For IP users, we should make ResourceError more specific.
            None => return ResourceError::PostgresError(error)

          };

          ResourceError::ConflictError(username)
          
        },
        
        _ => ResourceError::PostgresError(error)

      },

      None => ResourceError::PostgresError(error)

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

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<User, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/get-user-row-by-id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A user with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(ResourceError::NotFoundError(format!("A user with the ID \"{}\" does not exist.", id))),

          _ => return Err(ResourceError::PostgresError(error))

        },

        None => return Err(ResourceError::PostgresError(error))

      }

    };

    let user = User::from_row(&row);

    return Ok(user);

  }

  pub async fn get_by_ip_address(ip_address: &IpAddr, database_pool: &deadpool_postgres::Pool) -> Result<User, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/get-user-row-by-ip-address.sql");
    let row = match database_client.query_opt(query, &[&ip_address]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A user with the IP address \"{}\" does not exist.", ip_address)))

      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(ResourceError::NotFoundError(format!("A user with the IP address \"{}\" does not exist.", ip_address))),

          _ => return Err(ResourceError::PostgresError(error))

        },

        None => return Err(ResourceError::PostgresError(error))

      }

    };

    let user = User::from_row(&row);

    return Ok(user);

  }

  /// Initializes the users table.
  pub async fn initialize_users_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/initialize-users-table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub fn get_hashed_password(&self) -> &str {

    let hashed_password = self.hashed_password.as_ref().expect("User does not have a hashed password.");
    return &hashed_password;

  }

}