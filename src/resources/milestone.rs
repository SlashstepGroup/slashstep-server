pub struct Milestone {}

impl Milestone {

  /// Initializes the milestones table.
  pub fn initialize_milestones_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/milestones/initialize-milestones-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}