use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::resources::{DeletableResource, ResourceError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppAuthorizationCredential {

  /// The ID of the app authorization credential.
  pub id: Uuid,

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid,

  /// The expiration date of the access token.
  pub access_token_expiration_date: DateTime<Utc>,

  /// The expiration date of the refresh token.
  pub refresh_token_expiration_date: DateTime<Utc>,

  /// The ID of the refreshed app authorization credential, if applicable.
  pub refreshed_app_authorization_credential_id: Option<Uuid>

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialAppAuthorizationCredentialProperties {

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid,

  /// The expiration date of the access token.
  pub access_token_expiration_date: DateTime<Utc>,

  /// The expiration date of the refresh token.
  pub refresh_token_expiration_date: DateTime<Utc>,

  /// The ID of the refreshed app authorization credential, if applicable.
  pub refreshed_app_authorization_credential_id: Option<Uuid>

}

impl AppAuthorizationCredential {

  pub async fn create(initial_properties: &InitialAppAuthorizationCredentialProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app_authorization_credentials/insert_app_authorization_credential_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_authorization_id,
      &initial_properties.access_token_expiration_date,
      &initial_properties.refresh_token_expiration_date,
      &initial_properties.refreshed_app_authorization_credential_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization credential.
    let app_authorization_credential = Self::convert_from_row(&row);

    return Ok(app_authorization_credential);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/get_app_authorization_credential_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization_credential = Self::convert_from_row(&row);

    return Ok(app_authorization_credential);

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppAuthorizationCredential {
      id: row.get("id"),
      app_authorization_id: row.get("app_authorization_id"),
      access_token_expiration_date: row.get("access_token_expiration_date"),
      refresh_token_expiration_date: row.get("refresh_token_expiration_date"),
      refreshed_app_authorization_credential_id: row.get("refreshed_app_authorization_credential_id")
    };

  }

  /// Initializes the app_authorization_credentials table.
  pub async fn initialize_app_authorization_credentials_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/initialize_app_authorization_credentials_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}

impl DeletableResource for AppAuthorizationCredential {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/delete_app_authorization_credential_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}