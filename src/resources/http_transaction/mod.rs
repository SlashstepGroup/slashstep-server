#[cfg(test)]
mod tests;

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "method",
  "url",
  "ip_address",
  "headers",
  "status_code",
  "expiration_date"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id"
];
pub const RESOURCE_NAME: &str = "HTTPTransaction";
pub const DATABASE_TABLE_NAME: &str = "http_transactions";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.httpTransactions.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialHTTPTransactionProperties {

  /// The HTTP method of the HTTP request.
  pub method: String,

  /// The URL of the HTTP request.
  pub url: String,

  /// The IP address of the HTTP request.
  pub ip_address: IpAddr,

  /// The headers of the HTTP request.
  pub headers: String,

  /// The status code of the HTTP request.
  pub status_code: Option<i32>,

  /// The expiration date of the HTTP request.
  pub expiration_date: Option<DateTime<Utc>>

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct HTTPTransaction {

  /// The ID of the HTTP transaction.
  pub id: Uuid,

  /// The HTTP method of the HTTP request.
  pub method: String,

  /// The URL of the HTTP request.
  pub url: String,

  /// The IP address of the HTTP request.
  pub ip_address: IpAddr,

  /// The headers of the HTTP request.
  pub headers: String,

  /// The status code of the HTTP request.
  pub status_code: Option<i32>,

  /// The expiration date of the HTTP request.
  pub expiration_date: Option<DateTime<Utc>>

}

impl HTTPTransaction {

  /// Counts the number of http_transactions based on a query.
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
    let query = include_str!("../../queries/http_transactions/get_http_transaction_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A field value with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return HTTPTransaction {
      id: row.get("id"),
      method: row.get("method"),
      url: row.get("url"),
      ip_address: row.get("ip_address"),
      headers: row.get("headers"),
      status_code: row.get("status_code"),
      expiration_date: row.get("expiration_date")
    };

  }

  /// Initializes the http_transactions table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/http_transactions/initialize_http_transactions_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialHTTPTransactionProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/http_transactions/insert_http_transaction_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.method,
      &initial_properties.url,
      &initial_properties.ip_address,
      &initial_properties.headers,
      &initial_properties.status_code,
      &initial_properties.expiration_date
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

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

  /// Returns a list of http_transactions based on a query.
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
    let actions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(actions);

  }

}

impl DeletableResource for HTTPTransaction {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/http_transactions/delete_http_transaction_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}