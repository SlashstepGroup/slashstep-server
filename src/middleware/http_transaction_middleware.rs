use std::{net::SocketAddr, sync::Arc};
use axum::{body::Body, extract::{ConnectInfo, Request, State}, middleware::Next, response::{IntoResponse, Response}};
use chrono::{Duration, Utc};
use rust_decimal::prelude::ToPrimitive;
use crate::{AppState, HTTPError, resources::{ResourceError, http_transaction::{EditableHTTPTransactionProperties, HTTPTransaction, InitialHTTPTransactionProperties}, server_log_entry::ServerLogEntry}, utilities::route_handler_utilities::get_configuration_by_name};

pub async fn create_http_transaction(
  ConnectInfo(address): ConnectInfo<SocketAddr>,
  State(state): State<AppState>,
  mut request: Request<Body>, 
  next: Next
) -> Result<Response, HTTPError> {

  // Remove sensitive headers from the stored request.
  let client_ip = address.ip();
  let method = request.method().to_string();
  let url = request.uri().to_string();
  let mut safe_headers = request.headers().clone();
  safe_headers.remove("authorization");
  safe_headers.remove("cookie");
  let headers_json_string: serde_json::Value = format!("{:?}", safe_headers).into();

  // Create the HTTP request and add it to the request extension.
  let mut http_transaction = match HTTPTransaction::create(&InitialHTTPTransactionProperties {
    method,
    url,
    ip_address: client_ip,
    headers: headers_json_string.to_string(),
    status_code: None,
    expiration_timestamp: None
  }, &state.database_pool).await {

    Ok(http_transaction) => Arc::new(http_transaction),

    Err(error) => {

      let http_error = match error {

        ResourceError::PostgresError(postgres_error) => {
          
          match postgres_error.as_db_error() {
            
            Some(db_error) => HTTPError::InternalServerError(Some(format!("{:?}", db_error))),

            None => HTTPError::InternalServerError(Some(format!("{:?}", postgres_error)))

          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      ServerLogEntry::from_http_error(&http_error, None, &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let should_http_transactions_expire_configuration = get_configuration_by_name("httpTransactions.shouldExpire", &http_transaction, &state.database_pool).await?;
  let should_http_transactions_expire = should_http_transactions_expire_configuration.boolean_value.or(should_http_transactions_expire_configuration.default_boolean_value).unwrap_or(false);
  if should_http_transactions_expire {

    let expiration_duration_milliseconds = match should_http_transactions_expire_configuration.number_value
      .or(should_http_transactions_expire_configuration.default_number_value)
      .and_then(|decimal| decimal.to_i64())
    {

      Some(milliseconds) => Some(Duration::milliseconds(milliseconds)),

      None => None

    };

    if let Some(duration) = expiration_duration_milliseconds {

      http_transaction = match http_transaction.update(&EditableHTTPTransactionProperties {
        expiration_timestamp: Some(Some(Utc::now() + duration)),
        ..Default::default()
      }, &state.database_pool).await {

        Ok(updated_http_transaction) => Arc::new(updated_http_transaction),

        Err(error) => {

          let http_error = HTTPError::InternalServerError(Some(format!("Failed to set HTTP transaction expiration timestamp: {:?}", error)));
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
          return Err(http_error);

        }

      }
      
    }

  }

  request.extensions_mut().insert(http_transaction.clone());
  
  ServerLogEntry::info(&format!("HTTP request handling started."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response = next.run(request).await;
  return Ok(response);

}