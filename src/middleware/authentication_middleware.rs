use std::sync::Arc;

use axum::{Extension, body::Body, extract::{Request, State}, middleware::Next, response::{IntoResponse, Response}};
use axum_extra::extract::CookieJar;
use uuid::Uuid;
use crate::{AppState, HTTPError, handle_pool_error, resources::{http_transaction::HTTPTransaction, role::Role, role_memberships::{InitialRoleMembershipProperties, RoleMembership}, server_log_entry::ServerLogEntry, session::{Session, SessionError, SessionTokenClaims}, user::{InitialUserProperties, User, UserError}}};

async fn get_jwt_public_key(http_transaction_id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<String, Response> {

  let jwt_public_key = match Session::get_json_web_token_public_key().await {

    Ok(jwt_public_key) => jwt_public_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("{:?}", error)));
      let _ = http_error.print_and_save(Some(http_transaction_id), postgres_client).await;
      return Err(http_error.into_response());

    }

  };

  return Ok(jwt_public_key);

}

async fn get_decoding_key(http_transaction_id: &Uuid, postgres_client: &mut deadpool_postgres::Client, jwt_public_key: &str) -> Result<jsonwebtoken::DecodingKey, Response> {

  let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_pem(&jwt_public_key.as_bytes()) {
    Ok(decoding_key) => decoding_key,
    Err(error) => {
      
      let http_error = HTTPError::InternalServerError(Some(format!("Failed to decode JWT public key: {:?}", error)));
      let _ = http_error.print_and_save(Some(&http_transaction_id), postgres_client).await;
      return Err(http_error.into_response());

    }
  };

  return Ok(decoding_key);

}

async fn get_decoded_claims(http_transaction_id: &Uuid, postgres_client: &mut deadpool_postgres::Client, session_token: &str, decoding_key: &jsonwebtoken::DecodingKey, validation: &jsonwebtoken::Validation) -> Result<jsonwebtoken::TokenData<SessionTokenClaims>, Response> {

  let decoded_claims = match jsonwebtoken::decode::<SessionTokenClaims>(&session_token, &decoding_key, &validation) {
    Ok(decoded_claims) => decoded_claims,
    Err(error) => {

      let http_error = match &error.kind() {

        jsonwebtoken::errors::ErrorKind::InvalidToken => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),

        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claims) => {
         
          let _ = ServerLogEntry::warning(&format!("Missing required claim \"{}\" in session token.", claims), Some(&http_transaction_id), postgres_client).await;
          HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()))
          
        },

        _ => HTTPError::InternalServerError(Some(format!("Failed to decode session token: {:?}", error)))

      };

      let _ = http_error.print_and_save(Some(&http_transaction_id), postgres_client).await;
      return Err(http_error.into_response());

    }
  };

  return Ok(decoded_claims);

}

async fn get_user_by_id(http_transaction_id: &Uuid, postgres_client: &mut deadpool_postgres::Client, user_id: &Uuid) -> Result<User, Response> {

  let user = match User::get_by_id(&user_id, postgres_client).await {
    Ok(user) => user,
    Err(error) => {

      let http_error = match error {

        // For this middleware, signalling that the token is invalid is a higher priority than the user not existing.
        UserError::NotFoundError(_, _) => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),
        _ => HTTPError::InternalServerError(Some(error.to_string()))
        
      };

      let _ = http_error.print_and_save(Some(&http_transaction_id), postgres_client).await;

      return Err(http_error.into_response());

    }
  };

  return Ok(user);

}

async fn get_session_by_id(http_transaction_id: &Uuid, postgres_client: &mut deadpool_postgres::Client, session_id: &Uuid) -> Result<Session, Response> {

  let session = match Session::get_by_id(&session_id, postgres_client).await {
    Ok(session) => session,
    Err(error) => {

      let http_error = match error {
        SessionError::NotFoundError(_) => HTTPError::UnauthorizedError(Some(format!("Session with ID {} not found.", session_id))),
        SessionError::PostgresError(error) => match error.as_db_error() {
          
          Some(db_error) => HTTPError::InternalServerError(Some(format!("{:?}", db_error))),

          None => HTTPError::InternalServerError(Some(format!("{:?}", error)))
          
        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };

      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), postgres_client).await;

      return Err(http_error.into_response());

    }
  };

  return Ok(session);

}

#[axum_macros::debug_middleware]
pub async fn authenticate_user(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  cookie_jar: CookieJar, 
  mut request: Request<Body>,
  next: Next
) -> Result<Response, Response> {

  // Get the cookie from the request.
  let mut postgres_client = state.database_pool.get().await.map_err(handle_pool_error)?;

  let Some(session_token) = cookie_jar.get("sessionToken") else {

    // Use an anonymous user.
    let _ = ServerLogEntry::trace("No user token found in request. Checking for existing anonymous user...", Some(&http_transaction.id), &mut postgres_client).await;

    let ip_user = match User::get_by_ip_address(&http_transaction.ip_address, &mut postgres_client).await {
    
      Ok(ip_user) => Arc::new(ip_user),
    
      Err(error) => {
    
        match error {
    
          UserError::NotFoundError(_, _) => {
    
            let _ = ServerLogEntry::trace("No existing anonymous user found. Creating a new one...", Some(&http_transaction.id), &mut postgres_client).await;
            let anonymous_user = match User::create(&InitialUserProperties {
              username: None,
              display_name: None,
              hashed_password: None,
              is_anonymous: true,
              ip_address: Some(http_transaction.ip_address)
            }, &mut postgres_client).await {

              Ok(anonymous_user) => Arc::new(anonymous_user),

              Err(error) => {

                let http_error = HTTPError::InternalServerError(Some(format!("Failed to create anonymous user: {:?}", error)));
                let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
                return Err(http_error.into_response());

              }

            };
    
            anonymous_user
    
          },
    
          _ => {
    
            let http_error = HTTPError::InternalServerError(Some(format!("Failed to get anonymous user: {:?}", error)));
            let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
            return Err(http_error.into_response());
    
          }
    
        }
    
      }
    
    };
    
    let _ = ServerLogEntry::trace("Getting anonymous-users role...", Some(&http_transaction.id), &mut postgres_client).await;
    let anonymous_users_role = match Role::get_by_name("anonymous-users", &mut postgres_client).await {

      Ok(anonymous_users_role) => anonymous_users_role,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to get anonymous-users role: {:?}", error)));
        let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
        return Err(http_error.into_response());

      }

    };
    let _ = ServerLogEntry::trace(&format!("Checking if user {} has the anonymous-users role...", ip_user.id), Some(&http_transaction.id), &mut postgres_client).await;
    let role_memberships = match RoleMembership::list(&format!("role_id = \"{}\" and principal_type = \"User\" and principal_user_id = \"{}\"", anonymous_users_role.id, ip_user.id), &mut postgres_client).await {

      Ok(role_memberships) => role_memberships,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to get role memberships: {:?}", error)));
        let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
        return Err(http_error.into_response());

      }

    };

    if role_memberships.len() == 0 {

      let _ = ServerLogEntry::trace("User does not have the anonymous-users role. Creating a new role membership...", Some(&http_transaction.id), &mut postgres_client).await;
      let _ = RoleMembership::create(&InitialRoleMembershipProperties {
        role_id: &anonymous_users_role.id,
        principal_type: &crate::resources::role_memberships::RoleMembershipPrincipalType::User,
        principal_user_id: Some(&ip_user.id),
        principal_app_id: None,
        principal_group_id: None
      }, &mut postgres_client).await;
    
    }
    
    let _ = ServerLogEntry::trace(&format!("Adding user {} to request extensions...", ip_user.id), Some(&http_transaction.id), &mut postgres_client).await;

    request.extensions_mut().insert(Some(ip_user.clone()));

    let _ = ServerLogEntry::info(&format!("Authenticated as anonymous user {}.", ip_user.id), Some(&http_transaction.id), &mut postgres_client).await;

    return Ok(next.run(request).await);

  };

  if !session_token.value().starts_with("Bearer ") {

    let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()));
    let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
    return Err(http_error.into_response());

  }

  let session_token = session_token.value().to_string().replace("Bearer ", "");

  // Make sure the user token is valid.
  let _ = ServerLogEntry::trace("Decoding session token...", Some(&http_transaction.id), &mut postgres_client).await;

  let jwt_public_key = get_jwt_public_key(&http_transaction.id, &mut postgres_client).await?;
  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
  let decoding_key = get_decoding_key(&http_transaction.id, &mut postgres_client, &jwt_public_key).await?;
  let decoded_claims = get_decoded_claims(&http_transaction.id, &mut postgres_client, &session_token, &decoding_key, &validation).await?;

  // Set the user and session in the request extensions.
  let session_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error.into_response());

    }
    
  };
  let user_id = match Uuid::parse_str(&decoded_claims.claims.sub) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error.into_response());

    }
    
  };
  let _ = ServerLogEntry::trace("Getting session...", Some(&http_transaction.id), &mut postgres_client).await;
  let session = get_session_by_id(&http_transaction.id, &mut postgres_client, &session_id).await?;
  let _ = ServerLogEntry::trace("Getting user from session...", Some(&http_transaction.id), &mut postgres_client).await;
  let user = get_user_by_id(&http_transaction.id, &mut postgres_client, &user_id).await?;
  let _ = ServerLogEntry::trace("Adding user and session to request extensions...", Some(&http_transaction.id), &mut postgres_client).await;
  request.extensions_mut().insert(Some(Arc::new(user.clone())));
  request.extensions_mut().insert(Some(Arc::new(session.clone())));

  let _ = ServerLogEntry::info(&format!("Successfully authenticated as user {}.", user_id), Some(&http_transaction.id), &mut postgres_client).await;

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