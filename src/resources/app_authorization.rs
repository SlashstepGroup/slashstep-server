pub struct AppAuthorization {}

impl AppAuthorization {

  /// Initializes the app_authorizations table.
  pub fn initialize_app_authorizations_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/app-authorizations/initialize-app-authorizations-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}