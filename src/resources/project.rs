pub struct Project {}

impl Project {

  /// Initializes the projects table.
  pub fn initialize_projects_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/projects/initialize-projects-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}