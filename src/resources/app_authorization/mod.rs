use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::resources::ResourceError;

#[derive(Debug, Clone, ToSql, FromSql)]
#[postgres(name = "app_authorization_parent_resource_type")]
pub enum AppAuthorizationParentResourceType {
  Instance,
  Workspace,
  User
}

pub struct AppAuthorization {

  /// The ID of the app authorization.
  pub id: Uuid,

  /// The ID of the app.
  pub app_id: Uuid,

  /// The parent resource type of the app authorization.
  pub parent_resource_type: AppAuthorizationParentResourceType,

  /// The ID of the parent workspace of the app authorization, if applicable.
  pub parent_workspace_id: Option<Uuid>,

  /// The ID of the parent user of the app authorization, if applicable.
  pub parent_user_id: Option<Uuid>

}

impl AppAuthorization {

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app-authorizations/get-app-authorization-row-by-id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization = AppAuthorization::from_row(&row);

    return Ok(app_authorization);

  }

  fn from_row(row: &postgres::Row) -> Self {

    return AppAuthorization {
      id: row.get("id"),
      app_id: row.get("app_id"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_user_id: row.get("parent_user_id")
    };

  }

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app-authorizations/initialize-app-authorizations-table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}