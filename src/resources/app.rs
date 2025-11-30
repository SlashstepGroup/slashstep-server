use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct App {}

impl App {

  /// Initializes the apps table.
  pub async fn initialize_apps_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppError> {

    let query = include_str!("../queries/apps/initialize-apps-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}