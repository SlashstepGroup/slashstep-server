#[cfg(test)]
mod tests;

use std::{net::IpAddr};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Header;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "user_id",
  "expiration_date",
  "creation_ip_address"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "user_id"
];
pub const RESOURCE_NAME: &str = "Session";
pub const DATABASE_TABLE_NAME: &str = "sessions";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.sessions.get";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {

  /// The session's ID.
  pub id: Uuid,

  /// The session's user ID.
  pub user_id: Uuid,

  /// The session's expiration date.
  pub expiration_date: DateTime<Utc>,

  /// The IP address used to create the session.
  pub creation_ip_address: IpAddr

}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokenClaims {
  pub sub: String,
  pub jti: String,
  pub exp: usize
}

pub struct InitialSessionProperties {

  pub user_id: Uuid,

  pub expiration_date: DateTime<Utc>,

  pub creation_ip_address: IpAddr

}

impl Session {

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

  /// Gets a field by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/sessions/get_session_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A session with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let session = Self::convert_from_row(&row);

    return Ok(session);

  }

  /// Converts a row into a session.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Self {
      id: row.get("id"),
      user_id: row.get("user_id"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address")
    };

  }

  /// Initializes the sessions table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/sessions/initialize_sessions_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new session.
  pub async fn create(initial_properties: &InitialSessionProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let expiration_date = match DateTime::from_timestamp_millis(initial_properties.expiration_date.timestamp_millis()) {

      Some(expiration_date) => expiration_date,

      None => return Err(ResourceError::DateError(initial_properties.expiration_date))

    };
    let query = include_str!("../../queries/sessions/insert_session_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.user_id,
      &expiration_date,
      &initial_properties.creation_ip_address
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the session.
    let session = Self::convert_from_row(&row);

    return Ok(session);

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

  /// Returns a list of roles based on a query.
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
    let sessions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(sessions);

  }

  pub async fn generate_json_web_token(&self, private_key: &str) -> Result<String, ResourceError> {

    let claims = SessionTokenClaims {
      sub: self.user_id.to_string(),
      jti: self.id.to_string(),
      exp: (Utc::now() + Duration::days(30)).timestamp() as usize
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&Header::new(jsonwebtoken::Algorithm::EdDSA), &claims, &encoding_key)?;

    return Ok(token);

  }

}

impl DeletableResource for Session {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/sessions/delete_session_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;

    return Ok(());

  }

}