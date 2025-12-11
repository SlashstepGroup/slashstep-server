use std::net::IpAddr;
use postgres_types::ToSql;
use thiserror::Error;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
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

#[derive(Debug, Error)]
pub enum HTTPTransactionError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

impl HTTPTransaction {

  pub async fn create(properties: &InitialHTTPTransactionProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, HTTPTransactionError> {

    let query = include_str!("../../queries/http-transactions/insert-http-transaction-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.method,
      &properties.url,
      &properties.ip_address,
      &properties.headers,
      &properties.status_code,
      &properties.expiration_date
    ];
    let row = postgres_client.query_one(query, parameters).await?;

    let http_request = HTTPTransaction {
      id: row.get("id"),
      method: row.get("method"),
      url: row.get("url"),
      ip_address: row.get("ip_address"),
      headers: row.get("headers"),
      status_code: row.get("status_code"),
      expiration_date: row.get("expiration_date")
    };

    return Ok(http_request);

  }

  pub async fn initialize_http_transactions_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), HTTPTransactionError> {

    let query = include_str!("../../queries/http-transactions/create-http-transactions-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}