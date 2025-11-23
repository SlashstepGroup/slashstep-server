pub struct AppAuthorizationCredential {}

impl AppAuthorizationCredential {

  /// Initializes the app_authorization_credentials table.
  pub fn initialize_app_authorization_credentials_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/app-authorization-credentials/initialize-app-authorization-credentials-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}