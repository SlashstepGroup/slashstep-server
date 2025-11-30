use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppAuthorizationError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct AppAuthorization {}

impl AppAuthorization {

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppAuthorizationError> {

    let query = include_str!("../queries/app-authorizations/initialize-app-authorizations-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}