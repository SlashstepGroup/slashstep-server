use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AppAuthorizationCredentialError {
  #[error("An app authorization credential with the ID \"{0}\" does not exist.")]
  NotFoundError(String),
  
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct AppAuthorizationCredential {

  /// The ID of the app authorization credential.
  pub id: Uuid,

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid

}

impl AppAuthorizationCredential {

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<Self, AppAuthorizationCredentialError> {

    let query = include_str!("../../queries/app-authorization-credentials/get-app-authorization-credential-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(AppAuthorizationCredentialError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(AppAuthorizationCredentialError::PostgresError(error))

    };

    let app_authorization_credential = AppAuthorizationCredential::from_row(&row);

    return Ok(app_authorization_credential);

  }

  fn from_row(row: &postgres::Row) -> Self {

    return AppAuthorizationCredential {
      id: row.get("id"),
      app_authorization_id: row.get("app_authorization_id")
    };

  }

  /// Initializes the app_authorization_credentials table.
  pub async fn initialize_app_authorization_credentials_table(postgres_client: &deadpool_postgres::Client) -> Result<(), AppAuthorizationCredentialError> {

    let query = include_str!("../../queries/app-authorization-credentials/initialize-app-authorization-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}