use std::net::IpAddr;

use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AppCredentialError {
  #[error("Couldn't find an app credential with the ID \"{0}\".")]
  NotFoundError(Uuid),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

#[derive(Debug)]
pub struct AppCredential {

  /// The app credential's ID.
  pub id: Uuid,

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's expiration date.
  pub expiration_date: DateTime<Utc>,

  pub creation_ip_address: IpAddr

}

pub struct InitialAppCredentialProperties {

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's expiration date.
  pub expiration_date: DateTime<Utc>,

  pub creation_ip_address: IpAddr

}

impl AppCredential {

  /// Initializes the app_credentials table.
  pub async fn initialize_app_credentials_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppCredentialError> {

    let query = include_str!("../../queries/app-credentials/initialize-app-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn from_row(row: &postgres::Row) -> Self {

    return AppCredential {
      id: row.get("id"),
      app_id: row.get("app_id"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address")
    };

  }

  pub async fn create(initial_properties: &InitialAppCredentialProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AppCredentialError> {

    let query = include_str!("../../queries/app-credentials/insert-app-credential-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.expiration_date,
      &initial_properties.creation_ip_address
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| {

      return AppCredentialError::PostgresError(error)
    
    })?;

    // Return the app credential.
    let app_credential = AppCredential::from_row(&row);

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

    let app_credential = AppCredential::from_row(&row);

    return Ok(app_credential);

  }

}