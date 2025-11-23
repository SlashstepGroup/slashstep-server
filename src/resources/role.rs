pub struct Role {}

impl Role {

  /// Initializes the roles table.
  pub fn initialize_roles_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/roles/initialize-roles-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}