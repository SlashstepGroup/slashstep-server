use uuid::Uuid;
use crate::resources::ResourceError;

pub struct AppAuthorizationCredential {

  /// The ID of the app authorization credential.
  pub id: Uuid,

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid

}

impl AppAuthorizationCredential {

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app-authorization-credentials/get-app-authorization-credential-row-by-id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization_credential = AppAuthorizationCredential::from_row(&row);

    return Ok(app_authorization_credential);

  }

  fn from_row(row: &postgres::Row) -> Self {

    return AppAuthorizationCredential {
      id: row.get("id"),
      app_authorization_id: row.get("app_authorization_id")
    };

  }

  /// Initializes the app_authorization_credentials table.
  pub async fn initialize_app_authorization_credentials_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app-authorization-credentials/initialize-app-authorization-credentials-table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}