use std::sync::Arc;

use axum::{Extension, body::Body, extract::{Request, State}, http::HeaderMap, middleware::Next, response::{Response}};
use axum_extra::extract::CookieJar;
use reqwest::header;
use uuid::Uuid;
use crate::{AppState, HTTPError, resources::{ResourceError, app::App, http_transaction::HTTPTransaction, role::Role, role_memberships::{InitialRoleMembershipProperties, RoleMembership}, server_log_entry::ServerLogEntry, session::{Session, SessionTokenClaims}, user::{InitialUserProperties, User}}, utilities::route_handler_utilities::{get_app_credential_from_id, get_app_from_id}};

async fn get_jwt_public_key(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<String, HTTPError> {

  let jwt_public_key = match Session::get_json_web_token_public_key().await {

    Ok(jwt_public_key) => jwt_public_key,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("{:?}", error)));
      http_error.print_and_save(Some(http_transaction_id), database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(jwt_public_key);

}

async fn get_decoding_key(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, jwt_public_key: &str) -> Result<jsonwebtoken::DecodingKey, HTTPError> {

  let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_pem(&jwt_public_key.as_bytes()) {
    Ok(decoding_key) => decoding_key,
    Err(error) => {
      
      let http_error = HTTPError::InternalServerError(Some(format!("Failed to decode JWT public key: {:?}", error)));
      http_error.print_and_save(Some(&http_transaction_id), database_pool).await.ok();
      return Err(http_error);

    }
  };

  return Ok(decoding_key);

}

async fn get_decoded_claims(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, session_token: &str, decoding_key: &jsonwebtoken::DecodingKey, validation: &jsonwebtoken::Validation) -> Result<jsonwebtoken::TokenData<SessionTokenClaims>, HTTPError> {

  let decoded_claims = match jsonwebtoken::decode::<SessionTokenClaims>(&session_token, &decoding_key, &validation) {
    Ok(decoded_claims) => decoded_claims,
    Err(error) => {

      let http_error = match &error.kind() {

        jsonwebtoken::errors::ErrorKind::InvalidToken => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),

        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claims) => {
         
          ServerLogEntry::warning(&format!("Missing required claim \"{}\" in session token.", claims), Some(&http_transaction_id), database_pool).await.ok();
          HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()))
          
        },

        _ => HTTPError::InternalServerError(Some(format!("Failed to decode session token: {:?}", error)))

      };

      http_error.print_and_save(Some(&http_transaction_id), database_pool).await.ok();
      return Err(http_error);

    }
  };

  return Ok(decoded_claims);

}

async fn get_user_by_id(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, user_id: &Uuid) -> Result<User, HTTPError> {

  let user = match User::get_by_id(&user_id, database_pool).await {
    Ok(user) => user,
    Err(error) => {

      let http_error = match error {

        // For this middleware, signalling that the token is invalid is a higher priority than the user not existing.
        ResourceError::NotFoundError(_) => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),
        _ => HTTPError::InternalServerError(Some(error.to_string()))
        
      };

      http_error.print_and_save(Some(&http_transaction_id), database_pool).await.ok();

      return Err(http_error);

    }
  };

  return Ok(user);

}

async fn get_session_by_id(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, session_id: &Uuid) -> Result<Session, HTTPError> {

  let session = match Session::get_by_id(&session_id, database_pool).await {
    Ok(session) => session,
    Err(error) => {

      let http_error = match error {
        ResourceError::NotFoundError(_) => HTTPError::UnauthorizedError(Some(format!("Session with ID {} not found.", session_id))),
        ResourceError::PostgresError(error) => match error.as_db_error() {
          
          Some(db_error) => HTTPError::InternalServerError(Some(format!("{:?}", db_error))),

          None => HTTPError::InternalServerError(Some(format!("{:?}", error)))
          
        },
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), database_pool).await.ok();

      return Err(http_error);

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
) -> Result<Response, HTTPError> {

  // Get the cookie from the request.
  let Some(session_token) = cookie_jar.get("sessionToken") else {

    // Use an anonymous user.
    ServerLogEntry::trace("No user token found in request. Checking for existing anonymous user...", Some(&http_transaction.id), &state.database_pool).await.ok();

    let ip_user = match User::get_by_ip_address(&http_transaction.ip_address, &state.database_pool).await {
    
      Ok(ip_user) => Arc::new(ip_user),
    
      Err(error) => {
    
        match error {
    
          ResourceError::NotFoundError(_) => {
    
            ServerLogEntry::trace("No existing anonymous user found. Creating a new one...", Some(&http_transaction.id), &state.database_pool).await.ok();
            let anonymous_user = match User::create(&InitialUserProperties {
              username: None,
              display_name: None,
              hashed_password: None,
              is_anonymous: true,
              ip_address: Some(http_transaction.ip_address)
            }, &state.database_pool).await {

              Ok(anonymous_user) => Arc::new(anonymous_user),

              Err(error) => {

                let http_error = HTTPError::InternalServerError(Some(format!("Failed to create anonymous user: {:?}", error)));
                http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
                return Err(http_error);

              }

            };
    
            anonymous_user
    
          },
    
          _ => {
    
            let http_error = HTTPError::InternalServerError(Some(format!("Failed to get anonymous user: {:?}", error)));
            http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
            return Err(http_error);
    
          }
    
        }
    
      }
    
    };
    
    ServerLogEntry::trace("Getting anonymous-users role...", Some(&http_transaction.id), &state.database_pool).await.ok();
    let anonymous_users_role = match Role::get_by_name("anonymous-users", &state.database_pool).await {

      Ok(anonymous_users_role) => anonymous_users_role,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to get anonymous-users role: {:?}", error)));
        http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };
    ServerLogEntry::trace(&format!("Checking if user {} has the anonymous-users role...", ip_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();
    let role_memberships = match RoleMembership::list(&format!("role_id = \"{}\" and principal_type = \"User\" and principal_user_id = \"{}\"", anonymous_users_role.id, ip_user.id), &state.database_pool).await {

      Ok(role_memberships) => role_memberships,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to get role memberships: {:?}", error)));
        http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    if role_memberships.len() == 0 {

      ServerLogEntry::trace("User does not have the anonymous-users role. Creating a new role membership...", Some(&http_transaction.id), &state.database_pool).await.ok();
      RoleMembership::create(&InitialRoleMembershipProperties {
        role_id: &anonymous_users_role.id,
        principal_type: &crate::resources::role_memberships::RoleMembershipPrincipalType::User,
        principal_user_id: Some(&ip_user.id),
        principal_app_id: None,
        principal_group_id: None
      }, &state.database_pool).await.ok();
    
    }
    
    ServerLogEntry::trace(&format!("Adding user {} to request extensions...", ip_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();

    request.extensions_mut().insert(Some(ip_user.clone()));

    ServerLogEntry::info(&format!("Authenticated as anonymous user {}.", ip_user.id), Some(&http_transaction.id), &state.database_pool).await.ok();

    return Ok(next.run(request).await);

  };

  if !session_token.value().starts_with("Bearer ") {

    let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()));
    http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let session_token = session_token.value().to_string().replace("Bearer ", "");

  // Make sure the user token is valid.
  ServerLogEntry::trace("Decoding session token...", Some(&http_transaction.id), &state.database_pool).await.ok();

  let jwt_public_key = get_jwt_public_key(&http_transaction.id, &state.database_pool).await?;
  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
  let decoding_key = get_decoding_key(&http_transaction.id, &state.database_pool, &jwt_public_key).await?;
  let decoded_claims = get_decoded_claims(&http_transaction.id, &state.database_pool, &session_token, &decoding_key, &validation).await?;

  // Set the user and session in the request extensions.
  let session_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }
    
  };
  let user_id = match Uuid::parse_str(&decoded_claims.claims.sub) {
    
    Ok(user_id) => user_id,
    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the user ID.".to_string()));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }
    
  };
  ServerLogEntry::trace("Getting session...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let session = get_session_by_id(&http_transaction.id, &state.database_pool, &session_id).await?;
  ServerLogEntry::trace("Getting user from session...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let user = get_user_by_id(&http_transaction.id, &state.database_pool, &user_id).await?;
  ServerLogEntry::trace("Adding user and session to request extensions...", Some(&http_transaction.id), &state.database_pool).await.ok();
  request.extensions_mut().insert(Some(Arc::new(user.clone())));
  request.extensions_mut().insert(Some(Arc::new(session.clone())));

  ServerLogEntry::info(&format!("Successfully authenticated as user {}.", user_id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let response = next.run(request).await;

  return Ok(response);

}

#[axum_macros::debug_middleware]
pub async fn authenticate_app(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>, 
  headers: HeaderMap,
  mut request: Request<Body>,
  next: Next
) -> Result<Response, HTTPError> {
  
  // Get the cookie from the request.
  let Some(authorization_token) = headers.get(header::AUTHORIZATION) else {

    ServerLogEntry::info(&format!("No app token found in request."), Some(&http_transaction.id), &state.database_pool).await.ok();
    request.extensions_mut().insert(None as Option<Arc<App>>);
    return Ok(next.run(request).await);

  };

  let authorization_token = match authorization_token.to_str() {

    Ok(authorization_token) => authorization_token,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("Please provide a valid app token.".to_string()));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  if !authorization_token.starts_with("App ") {

    let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid app token.".to_string()));
    http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  let authorization_token = authorization_token.to_string().replace("App ", "");

  // Make sure the user token is valid.
  ServerLogEntry::trace("Decoding app token...", Some(&http_transaction.id), &state.database_pool).await.ok();

  let jwt_public_key = get_jwt_public_key(&http_transaction.id, &state.database_pool).await?;
  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
  let decoding_key = get_decoding_key(&http_transaction.id, &state.database_pool, &jwt_public_key).await?;
  let decoded_claims = get_decoded_claims(&http_transaction.id, &state.database_pool, &authorization_token, &decoding_key, &validation).await?;

  // Set the user and session in the request extensions.
  let app_credential_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
    
    Ok(app_credential_id) => app_credential_id,

    Err(_) => {

      let http_error = HTTPError::InternalServerError(Some("App credential ID is not a valid UUID.".to_string()));
      http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }
    
  };

  let app_credential = match get_app_credential_from_id(&app_credential_id.to_string(), &http_transaction, &state.database_pool).await {

    Ok(app_credential) => app_credential,

    Err(error) => match error {

      HTTPError::BadRequestError(_) | HTTPError::NotFoundError(_) => {

        let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid app token.".to_string()));
        http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      },

      _ => return Err(error)

    }

  };

  let app = match get_app_from_id(&app_credential.app_id.to_string(), &http_transaction, &state.database_pool).await {

    Ok(app) => app,

    Err(error) => match error {

      HTTPError::BadRequestError(_) | HTTPError::NotFoundError(_) => {

        let http_error = HTTPError::UnauthorizedError(Some("Please provide a valid app token.".to_string()));
        http_error.print_and_save(Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      },

      _ => return Err(error)

    }

  };
  
  ServerLogEntry::trace("Adding app and app credential to request extensions...", Some(&http_transaction.id), &state.database_pool).await.ok();
  request.extensions_mut().insert(Some(Arc::new(app.clone())));
  request.extensions_mut().insert(Some(Arc::new(app_credential.clone())));

  ServerLogEntry::info(&format!("Successfully authenticated as app {}.", app.id), Some(&http_transaction.id), &state.database_pool).await.ok();

  let response = next.run(request).await;

  return Ok(response);

}