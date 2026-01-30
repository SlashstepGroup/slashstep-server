use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkspaceError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Workspace {}

impl Workspace {

  /// Initializes the workspaces table.
  pub async fn initialize_workspaces_table(postgres_client: &deadpool_postgres::Client) -> Result<(), WorkspaceError> {

    let query = include_str!("../../queries/workspaces/initialize-workspaces-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}