use std::{net::IpAddr};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Header;
use postgres::error::SqlState;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::resources::ResourceError;

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
  pub jti: String,
  pub exp: usize
}

pub struct InitialSessionProperties<'a> {

  pub user_id: &'a Uuid,

  pub expiration_date: &'a DateTime<Utc>,

  pub creation_ip_address: &'a IpAddr

}

impl Session {

  pub async fn get_json_web_token_public_key() -> Result<String, ResourceError> {

    let jwt_public_key_path = std::env::var("JWT_PUBLIC_KEY_PATH")?;
    let jwt_public_key = std::fs::read_to_string(&jwt_public_key_path)?;

    return Ok(jwt_public_key);

  }

  pub async fn get_json_web_token_private_key() -> Result<String, ResourceError> {

    let jwt_private_key_path = std::env::var("JWT_PRIVATE_KEY_PATH")?;
    let jwt_private_key = std::fs::read_to_string(&jwt_private_key_path)?;

    return Ok(jwt_private_key);

  }

  /// Initializes the sessions table.
  pub async fn initialize_sessions_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/sessions/initialize-sessions-table.sql");
    database_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/sessions/initialize-hydrated-sessions-view.sql");
    database_client.execute(query, &[]).await?;

    return Ok(());

  }

  pub async fn create<'a>(properties: &InitialSessionProperties<'a>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/sessions/insert-session-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.user_id,
      &properties.expiration_date,
      &properties.creation_ip_address
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await?;

    let session = Session {
      id: row.get("id"),
      user_id: row.get("user_id"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address")
    };

    return Ok(session);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Session, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/sessions/get-session-row-by-id.sql");
    let row = match database_client.query_one(query, &[&id]).await {

      Ok(row) => row,

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::NO_DATA_FOUND => return Err(ResourceError::NotFoundError(format!("A session with the ID \"{}\" does not exist.", id))),

          _ => return Err(ResourceError::PostgresError(error))

        },

        None => return Err(ResourceError::PostgresError(error))

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

  pub async fn generate_json_web_token(&self, private_key: &str) -> Result<String, ResourceError> {

    let claims = SessionTokenClaims {
      sub: self.user_id.to_string(),
      jti: self.id.to_string(),
      exp: (Utc::now() + Duration::days(30)).timestamp() as usize
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&Header::new(jsonwebtoken::Algorithm::RS256), &claims, &encoding_key)?;

    return Ok(token);

  }

}