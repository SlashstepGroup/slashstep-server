use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Group {}

impl Group {

  /// Initializes the groups table.
  pub async fn initialize_groups_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), GroupError> {

    let query = include_str!("../queries/groups/initialize-groups-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}