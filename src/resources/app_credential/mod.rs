use std::net::IpAddr;
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;


#[derive(Debug, Error)]
pub enum AppCredentialError {
  #[error("Couldn't find an app credential with the ID \"{0}\".")]
  NotFoundError(Uuid),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

/// A credential that can be used to generate JSON web tokens (JWT) for apps so that they can authenticate with Slashstep Server.
/// To protect the app, Slashstep Server only stores the app credential's metadata and public key. App admins are responsible for managing the private key. 
#[derive(Debug, Serialize, Deserialize)]
pub struct AppCredential {

  /// The app credential's ID.
  pub id: Uuid,

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>,

  /// The app credential's creation IP address.
  pub creation_ip_address: IpAddr,

  /// The app credential's public key.
  pub public_key: String

}

pub struct InitialAppCredentialProperties {

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>,

  /// The app credential's creation IP address.
  pub creation_ip_address: IpAddr,

  /// The app credential's public key.
  pub public_key: String

}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialAppCredentialPropertiesForPredefinedScope {

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>

}

impl AppCredential {

  /// Initializes the app_credentials table.
  pub async fn initialize_app_credentials_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppCredentialError> {

    let query = include_str!("../../queries/app-credentials/initialize-app-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppCredential {
      id: row.get("id"),
      app_id: row.get("app_id"),
      description: row.get("description"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address"),
      public_key: row.get("public_key")
    };

  }

  pub async fn create(initial_properties: &InitialAppCredentialProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AppCredentialError> {

    let query = include_str!("../../queries/app-credentials/insert-app-credential-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.description,
      &initial_properties.expiration_date,
      &initial_properties.creation_ip_address,
      &initial_properties.public_key
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| {

      return AppCredentialError::PostgresError(error)
    
    })?;

    // Return the app credential.
    let app_credential = AppCredential::convert_from_row(&row);

    return Ok(app_credential);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AppCredentialError> {

    let query = include_str!("../../queries/app-credentials/get-app-credential-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(AppCredentialError::NotFoundError(id.clone()))

      },

      Err(error) => return Err(AppCredentialError::PostgresError(error))

    };

    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

}