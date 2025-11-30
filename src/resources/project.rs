use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProjectError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Project {}

impl Project {

  /// Initializes the projects table.
  pub async fn initialize_projects_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), ProjectError> {

    let query = include_str!("../queries/projects/initialize-projects-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}