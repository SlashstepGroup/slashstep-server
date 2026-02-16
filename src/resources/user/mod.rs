/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use postgres::error::SqlState;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "username",
  "display_name",
  "is_anonymous",
  "ip_address"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id"
];
pub const RESOURCE_NAME: &str = "User";
pub const DATABASE_TABLE_NAME: &str = "users";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.users.get";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

  /// Counts the number of roles based on a query.
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

  /// Creates a new user.
  pub async fn create(initial_properties: &InitialUserProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/users/insert_user_row.sql");
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
    let user = Self {
      id: row.get("id"),
      username: row.get("username"),
      display_name: row.get("display_name"),
      hashed_password: row.get("hashed_password"),
      is_anonymous: row.get("is_anonymous"),
      ip_address: row.get("ip_address")
    };

    return Ok(user);

  }

  pub fn convert_from_row(row: &postgres::Row) -> Self {

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
    let query = include_str!("../../queries/users/get_user_row_by_id.sql");
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

    let user = User::convert_from_row(&row);

    return Ok(user);

  }

  pub async fn get_by_ip_address(ip_address: &IpAddr, database_pool: &deadpool_postgres::Pool) -> Result<User, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/get_user_row_by_ip_address.sql");
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

    let user = User::convert_from_row(&row);

    return Ok(user);

  }

  pub fn get_hashed_password(&self) -> &str {

    let hashed_password = self.hashed_password.as_ref().expect("User does not have a hashed password.");
    return &hashed_password;

  }

  /// Initializes the users table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/initialize_users_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Parses a string into a parameter for a slashstepql query.
  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    return Ok(Box::new(value));

  }

  /// Returns a list of users based on a query.
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
    let users = rows.iter().map(Self::convert_from_row).collect();
    return Ok(users);

  }

}

impl DeletableResource for User {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/users/delete_user_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}