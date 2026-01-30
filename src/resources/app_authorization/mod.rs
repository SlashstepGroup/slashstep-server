use thiserror::Error;
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};

#[derive(Debug, Clone, ToSql, FromSql)]
#[postgres(name = "app_authorization_parent_resource_type")]
pub enum AppAuthorizationParentResourceType {
  Instance,
  Workspace,
  User
}

#[derive(Debug, Error)]
pub enum AppAuthorizationError {
  #[error("An app authorization with the ID \"{0}\" does not exist.")]
  NotFoundError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
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

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<Self, AppAuthorizationError> {

    let query = include_str!("../../queries/app-authorizations/get-app-authorization-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(AppAuthorizationError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(AppAuthorizationError::PostgresError(error))

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
  pub async fn initialize_app_authorizations_table(postgres_client: &deadpool_postgres::Client) -> Result<(), AppAuthorizationError> {

    let query = include_str!("../../queries/app-authorizations/initialize-app-authorizations-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}