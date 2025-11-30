use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoleError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct Role {}

impl Role {

  /// Initializes the roles table.
  pub async fn initialize_roles_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), RoleError> {

    let query = include_str!("../queries/roles/initialize-roles-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}