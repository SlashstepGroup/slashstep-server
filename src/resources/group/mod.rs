use crate::resources::ResourceError;

pub struct Group {}

impl Group {

  /// Initializes the groups table.
  pub async fn initialize_groups_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let query = include_str!("../../queries/groups/initialize-groups-table.sql");
    let database_client = database_pool.get().await?;
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}