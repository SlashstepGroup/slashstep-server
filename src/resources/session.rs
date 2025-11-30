use std::{net::IpAddr};
use chrono::{DateTime, Utc};
use jsonwebtoken::Header;
use postgres::error::SqlState;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
  #[error("A session with the ID \"{0}\" does not exist.")]
  NotFoundError(Uuid),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  VarError(#[from] std::env::VarError),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  JSONWebTokenError(#[from] jsonwebtoken::errors::Error)
}

#[derive(Debug, Clone)]
pub struct Session {

  /// The session's ID.
  pub id: Uuid,

  /// The session's user ID.
  pub user_id: Uuid,

  /// The session's expiration date.
  pub expiration_date: DateTime<Utc>,

  /// The IP address used to create the session.
  pub creation_ip_address: IpAddr

}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokenClaims {
  pub sub: String,
  pub jti: String
}

pub struct InitialSessionProperties<'a> {

  pub user_id: &'a Uuid,

  pub expiration_date: &'a DateTime<Utc>,

  pub creation_ip_address: &'a IpAddr

}

impl Session {

  pub async fn get_json_web_token_public_key() -> Result<String, SessionError> {

    let jwt_public_key_path = std::env::var("JWT_PUBLIC_KEY_PATH")?;
    let jwt_public_key = std::fs::read_to_string(&jwt_public_key_path)?;

    return Ok(jwt_public_key);

  }

  pub async fn get_json_web_token_private_key() -> Result<String, SessionError> {

    let jwt_private_key_path = std::env::var("JWT_PRIVATE_KEY_PATH")?;
    let jwt_private_key = std::fs::read_to_string(&jwt_private_key_path)?;

    return Ok(jwt_private_key);

  }

  /// Initializes the sessions table.
  pub async fn initialize_sessions_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), SessionError> {

    let query = include_str!("../queries/sessions/initialize-sessions-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub async fn create<'a>(properties: &InitialSessionProperties<'a>, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, SessionError> {

    let query = include_str!("../queries/sessions/insert-session-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.user_id,
      &properties.expiration_date,
      &properties.creation_ip_address
    ];
    let row = postgres_client.query_one(query, parameters).await?;

    let session = Session {
      id: row.get("id"),
      user_id: row.get("user_id"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address")
    };

    return Ok(session);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Session, SessionError> {

    let query = include_str!("../queries/sessions/get-session-row-by-id.sql");
    let row = match postgres_client.query_one(query, &[&id]).await {

      Ok(row) => row,

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(SessionError::NotFoundError(id.clone())),

          _ => return Err(SessionError::PostgresError(error))

        },

        None => return Err(SessionError::PostgresError(error))

      }

    };

    let session = Session {
      id: row.get("id"),
      user_id: row.get("user_id"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address")
    };

    return Ok(session);

  }

  pub async fn generate_json_web_token(&self, jwt_secret: &str) -> Result<String, SessionError> {

    let claims = SessionTokenClaims {
      sub: self.user_id.to_string(),
      jti: self.id.to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_ref());
    let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)?;

    return Ok(token);

  }

}