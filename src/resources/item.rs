use thiserror::Error;

#[derive(Debug, Error)]
pub enum ItemError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Item {}

impl Item {

  /// Initializes the items table.
  pub async fn initialize_items_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), ItemError> {

    let query = include_str!("../queries/items/initialize-items-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}