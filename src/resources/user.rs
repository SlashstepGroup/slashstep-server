use std::net::IpAddr;

use postgres::error::SqlState;
use postgres_types::ToSql;
use uuid::Uuid;

use crate::errors::resource_already_exists_error::ResourceAlreadyExistsError;

/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

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

#[derive(Debug)]
pub enum UserCreationError<'a> {
  ResourceAlreadyExistsError(ResourceAlreadyExistsError<'a>),
  String(String),
  PostgresError(postgres::Error)
}

impl User {

  /// Creates a new user.
  pub fn create<'a>(initial_properties: &'a InitialUserProperties, postgres_client: &mut postgres::Client) -> Result<Self, UserCreationError<'a>> {

    // Insert the access policy into the database.
    let query = include_str!("../queries/users/insert-user-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.username,
      &initial_properties.display_name,
      &initial_properties.hashed_password,
      &initial_properties.is_anonymous,
      &initial_properties.ip_address
    ];
    let rows = postgres_client.query(query, parameters);

    // Return the action.
    match rows {

      Ok(rows) => {

        let row = rows.get(0).ok_or(UserCreationError::String("Client did not return a row.".to_string()))?;
        let user = User {
          id: row.get("id"),
          username: row.get("username"),
          display_name: row.get("display_name"),
          hashed_password: row.get("hashed_password"),
          is_anonymous: row.get("is_anonymous"),
          ip_address: row.get("ip_address")
        };

        return Ok(user);
        
      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => {

          let error_code = db_error.code();
          match error_code {

            &SqlState::UNIQUE_VIOLATION => {

              let resource_already_exists_error = ResourceAlreadyExistsError {
                resource_type: "Action"
              };

              Err(UserCreationError::ResourceAlreadyExistsError(resource_already_exists_error))

            },
            
            _ => {
              Err(UserCreationError::PostgresError(error))
            }

          }

        },

        None => {

          Err(UserCreationError::PostgresError(error))

        }

      }

    }

  }

  /// Initializes the users table.
  pub fn initialize_users_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/users/initialize-users-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

  pub fn get_hashed_password(&self) -> &str {

    let hashed_password = self.hashed_password.as_ref().expect("User does not have a hashed password.");
    return &hashed_password;

  }

}