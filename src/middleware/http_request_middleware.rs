use std::{net::SocketAddr, sync::Arc};
use axum::{body::Body, extract::{ConnectInfo, Request, State}, middleware::Next, response::{IntoResponse, Response}};
use chrono::{Duration, Utc};
use crate::{AppState, HTTPError, resources::{ResourceError, http_transaction::{HTTPTransaction, InitialHTTPTransactionProperties}, server_log_entry::ServerLogEntry}};

pub async fn create_http_request(
  ConnectInfo(address): ConnectInfo<SocketAddr>,
  State(state): State<AppState>,
  mut request: Request<Body>, 
  next: Next
) -> Result<Response, Response> {

  // Remove sensitive headers from the stored request.
  let client_ip = address.ip();
  let method = request.method().to_string();
  let url = request.uri().to_string();
  let mut safe_headers = request.headers().clone();
  safe_headers.remove("authorization");
  safe_headers.remove("cookie");
  let headers_json_string: serde_json::Value = format!("{:?}", safe_headers).into();

  // Create the HTTP request and add it to the request extension.
  let http_transaction = match HTTPTransaction::create(&InitialHTTPTransactionProperties {
    method,
    url,
    ip_address: client_ip,
    headers: headers_json_string.to_string(),
    status_code: None,
    expiration_date: Some(Utc::now() + Duration::days(30))
  }, &state.database_pool).await {

    Ok(http_request) => Arc::new(http_request),

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
      return Err(http_error.into_response());

    }

  };

  request.extensions_mut().insert(http_transaction.clone());
  
  ServerLogEntry::info(&format!("HTTP request handling started."), Some(&http_transaction.id), &state.database_pool).await.ok();
  let response = next.run(request).await;
  return Ok(response);

}