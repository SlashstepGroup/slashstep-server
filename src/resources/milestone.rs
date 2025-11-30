use thiserror::Error;

#[derive(Debug, Error)]
pub enum MilestoneError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Milestone {}

impl Milestone {

  /// Initializes the milestones table.
  pub async fn initialize_milestones_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), MilestoneError> {

    let query = include_str!("../queries/milestones/initialize-milestones-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}