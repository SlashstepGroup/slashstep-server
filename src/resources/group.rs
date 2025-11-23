pub struct Group {}

impl Group {

  /// Initializes the groups table.
  pub fn initialize_groups_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/groups/initialize-groups-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}