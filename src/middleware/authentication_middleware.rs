use std::sync::Arc;

use axum::{Extension, extract::{Request, State}, http::StatusCode, middleware::Next, response::Response};

use crate::{AppState, RequestData};

pub async fn authenticate_user(
  State(state): State<AppState>, 
  Extension(request_data): Extension<RequestData>,
  request: Request, 
  next: Next
) -> Result<Response, StatusCode> {

  // Call the next service in the stack (the handler or next middleware)
  let response = next.run(request).await;

  return Ok(response);
}

pub async fn authenticate_app(request: Request, next: Next) -> Result<Response, StatusCode> {
  // Perform actions before the handler
  
  println!("Request received: {}", request.uri());

  // Call the next service in the stack (the handler or next middleware)
  let response = next.run(request).await;

  // Perform actions after the handler
  println!("Response status: {}", response.status());

  return Ok(response);
}