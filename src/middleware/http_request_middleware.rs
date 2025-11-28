use std::net::SocketAddr;

use anyhow::Result;
use axum::{body::Body, extract::{ConnectInfo, Request, State}, middleware::Next, response::{Response, IntoResponse}, http::StatusCode};
use chrono::{Duration, Utc};
use crate::{AppState, HTTPError, resources::{http_request::{HTTPRequest, InitialHTTPRequestProperties}, server_log_entry::ServerLogEntry}};
use colored::Colorize;

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
  let mut postgres_client = state.database_pool.get().await.map_err(|error| {
    
    eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
    let http_error = HTTPError::InternalServerError(Some(error.to_string()));
    http_error.into_response()

  })?;

  let http_request = match HTTPRequest::create(&InitialHTTPRequestProperties {
    method,
    url,
    ip_address: client_ip,
    headers: headers_json_string.to_string(),
    status_code: None,
    expiration_date: Some(Utc::now() + Duration::days(30))
  }, &mut postgres_client).await {

    Ok(http_request) => http_request,

    Err(error) => {

      let http_error = match error.downcast_ref::<postgres::Error>() {

        Some(postgres_error) => {
          
          match postgres_error.as_db_error() {
            
            Some(db_error) => HTTPError::InternalServerError(Some(format!("{:?}", db_error))),

            None => HTTPError::InternalServerError(Some(format!("{:?}", postgres_error)))

          }

        },

        None => HTTPError::InternalServerError(Some(format!("{:?}", error)))

      };
      let _ = ServerLogEntry::from_http_error(&http_error, None, &mut postgres_client).await;
      return Err(http_error.into_response());

    }

  };

  
  let _ = ServerLogEntry::create_info_log(&format!("HTTP request handling started."), Some(http_request.id), &mut postgres_client).await;

  request.extensions_mut().insert(http_request);

  let response = next.run(request).await;
  return Ok(response);

}