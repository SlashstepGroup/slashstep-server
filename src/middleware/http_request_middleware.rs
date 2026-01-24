use std::{net::SocketAddr, sync::Arc};
use axum::{body::Body, extract::{ConnectInfo, Request, State}, middleware::Next, response::{IntoResponse, Response}};
use chrono::{Duration, Utc};
use crate::{AppState, HTTPError, handle_pool_error, resources::{http_transaction::{HTTPTransaction, HTTPTransactionError, InitialHTTPTransactionProperties}, server_log_entry::ServerLogEntry}};

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
  let mut postgres_client = state.database_pool.get().await.map_err(handle_pool_error)?;

  let http_request = match HTTPTransaction::create(&InitialHTTPTransactionProperties {
    method,
    url,
    ip_address: client_ip,
    headers: headers_json_string.to_string(),
    status_code: None,
    expiration_date: Some(Utc::now() + Duration::days(30))
  }, &mut postgres_client).await {

    Ok(http_request) => Arc::new(http_request),

    Err(error) => {

      let http_error = match error {

        HTTPTransactionError::PostgresError(postgres_error) => {
          
          match postgres_error.as_db_error() {
            
            Some(db_error) => HTTPError::InternalServerError(Some(format!("{:?}", db_error))),

            None => HTTPError::InternalServerError(Some(format!("{:?}", postgres_error)))

          }

        }

      };
      ServerLogEntry::from_http_error(&http_error, None, &mut postgres_client).await.ok();
      return Err(http_error.into_response());

    }

  };

  request.extensions_mut().insert(http_request.clone());
  
  ServerLogEntry::info(&format!("HTTP request handling started."), Some(&http_request.id), &mut postgres_client).await.ok();
  let response = next.run(request).await;
  return Ok(response);

}