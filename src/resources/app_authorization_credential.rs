use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppAuthorizationCredentialError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct AppAuthorizationCredential {}

impl AppAuthorizationCredential {

  /// Initializes the app_authorization_credentials table.
  pub async fn initialize_app_authorization_credentials_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppAuthorizationCredentialError> {

    let query = include_str!("../queries/app-authorization-credentials/initialize-app-authorization-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}