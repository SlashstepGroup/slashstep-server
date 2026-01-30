use crate::resources::ResourceError;

pub struct Workspace {}

impl Workspace {

  /// Initializes the workspaces table.
  pub async fn initialize_workspaces_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/workspaces/initialize-workspaces-table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}