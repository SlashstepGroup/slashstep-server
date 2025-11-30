use axum::{Extension, extract::{Request, State}, middleware::Next, response::{IntoResponse, Response}};
use axum_extra::extract::CookieJar;
use uuid::Uuid;
use crate::{AppState, HTTPError, RequestData, handle_pool_error, resources::{server_log_entry::ServerLogEntry, session::{Session, SessionError, SessionTokenClaims}, user::{User, UserError}}};

async fn get_jwt_public_key(request_data: &RequestData, postgres_client: &mut deadpool_postgres::Client) -> Result<String, Response> {

  let jwt_public_key = match Session::get_json_web_token_public_key().await {

    Ok(jwt_public_key) => jwt_public_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("{:?}", error)));
      let _ = http_error.print_and_save(Some(&request_data.http_request.id), postgres_client).await;
      return Err(http_error.into_response());

    }

  };

  return Ok(jwt_public_key);

}

async fn get_decoding_key(request_data: &RequestData, postgres_client: &mut deadpool_postgres::Client, jwt_public_key: &str) -> Result<jsonwebtoken::DecodingKey, Response> {

  let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_pem(&jwt_public_key.as_bytes()) {
    Ok(decoding_key) => decoding_key,
    Err(error) => {
      
      let http_error = HTTPError::InternalServerError(Some(format!("Failed to decode JWT public key: {:?}", error)));
      let _ = http_error.print_and_save(Some(&request_data.http_request.id), postgres_client).await;
      return Err(http_error.into_response());

    }
  };

  return Ok(decoding_key);

}

async fn get_decoded_claims(request_data: &RequestData, postgres_client: &mut deadpool_postgres::Client, session_token: &str, decoding_key: &jsonwebtoken::DecodingKey, validation: &jsonwebtoken::Validation) -> Result<jsonwebtoken::TokenData<SessionTokenClaims>, Response> {

  let decoded_claims = match jsonwebtoken::decode::<SessionTokenClaims>(&session_token, &decoding_key, &validation) {
    Ok(decoded_claims) => decoded_claims,
    Err(_) => {

      let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()));
      let _ = http_error.print_and_save(Some(&request_data.http_request.id), postgres_client).await;
      return Err(http_error.into_response());

    }
  };

  return Ok(decoded_claims);

}

async fn get_user_by_id(request_data: &RequestData, postgres_client: &mut deadpool_postgres::Client, user_id: &Uuid) -> Result<User, Response> {

  let user = match User::get_by_id(&user_id, postgres_client).await {
    Ok(user) => user,
    Err(error) => {

      let http_error = match error {

        // For this middleware, signalling that the token is invalid is a higher priority than the user not existing.
        UserError::NotFoundError(_) => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),
        _ => HTTPError::InternalServerError(Some(error.to_string()))
        
      };

      let _ = http_error.print_and_save(Some(&request_data.http_request.id), postgres_client).await;

      return Err(http_error.into_response());

    }
  };

  return Ok(user);

}

async fn get_session_by_id(request_data: &RequestData, postgres_client: &mut deadpool_postgres::Client, session_id: &Uuid) -> Result<Session, Response> {

  let session = match Session::get_by_id(&session_id, postgres_client).await {
    Ok(session) => session,
    Err(error) => {

      let http_error = match error {
        SessionError::NotFoundError(_) => HTTPError::UnauthorizedError(Some(format!("Session with ID {} not found.", session_id))),
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };

      let _ = ServerLogEntry::from_http_error(&http_error, Some(&request_data.http_request.id), postgres_client).await;

      return Err(http_error.into_response());

    }
  };

  return Ok(session);

}

pub async fn authenticate_user(
  State(state): State<AppState>, 
  Extension(request_data): Extension<RequestData>,
  cookie_jar: CookieJar,
  mut request: Request, 
  next: Next
) -> Result<Response, Response> {

  // Get the cookie from the request.
  let mut postgres_client = state.database_pool.get().await.map_err(handle_pool_error)?;

  let Some(session_token) = cookie_jar.get("sessionToken") else {

    let _ = ServerLogEntry::info("No user token found in request. Continuing...", Some(&request_data.http_request.id), &mut postgres_client).await;

    return Ok(next.run(request).await);

  };

  if !session_token.value().starts_with("Bearer ") {

    let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()));
    let _ = http_error.print_and_save(Some(&request_data.http_request.id), &mut postgres_client).await;
    return Err(http_error.into_response());

  }

  let session_token = session_token.value().to_string().replace("Bearer ", "");

  // Make sure the user token is valid.
  let _ = ServerLogEntry::trace("Authenticating as a user...", Some(&request_data.http_request.id), &mut postgres_client).await;

  let jwt_public_key = get_jwt_public_key(&request_data, &mut postgres_client).await?;
  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
  let decoding_key = get_decoding_key(&request_data, &mut postgres_client, &jwt_public_key).await?;
  let decoded_claims = get_decoded_claims(&request_data, &mut postgres_client, &session_token, &decoding_key, &validation).await?;

  // Set the user and session in the request extensions.
  let session_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      let _ = http_error.print_and_save(Some(&request_data.http_request.id), &mut postgres_client).await;
      return Err(http_error.into_response());

    }
    
  };
  let user_id = match Uuid::parse_str(&decoded_claims.claims.sub) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      let _ = http_error.print_and_save(Some(&request_data.http_request.id), &mut postgres_client).await;
      return Err(http_error.into_response());

    }
    
  };
  let session = get_session_by_id(&request_data, &mut postgres_client, &session_id).await?;
  let user = get_user_by_id(&request_data, &mut postgres_client, &user_id).await?;
  request.extensions_mut().insert(user.clone());
  request.extensions_mut().insert(session.clone());

  let _ = ServerLogEntry::info(&format!("Successfully authenticated as user {}", user_id), Some(&request_data.http_request.id), &mut postgres_client).await;

  let response = next.run(request).await;

  return Ok(response);

}

pub async fn authenticate_app(request: Request, next: Next) -> Result<Response, Response> {
  // Perform actions before the handler
  
  println!("Request received: {}", request.uri());

  // Call the next service in the stack (the handler or next middleware)
  let response = next.run(request).await;

  // Perform actions after the handler
  println!("Response status: {}", response.status());

  return Ok(response);
}