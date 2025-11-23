pub struct App {}

impl App {

  /// Initializes the apps table.
  pub fn initialize_apps_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/apps/initialize-apps-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}