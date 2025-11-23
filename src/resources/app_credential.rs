pub struct AppCredential {}

impl AppCredential {

  /// Initializes the app_credentials table.
  pub fn initialize_app_credentials_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/app-credentials/initialize-app-credentials-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}