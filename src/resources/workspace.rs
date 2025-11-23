pub struct Workspace {}

impl Workspace {

  /// Initializes the workspaces table.
  pub fn initialize_workspaces_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/workspaces/initialize-workspaces-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}