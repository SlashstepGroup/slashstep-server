use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::resources::{DeletableResource, ResourceError};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, Default, PartialEq, Eq)]
#[postgres(name = "app_authorization_authorizing_resource_type")]
pub enum AppAuthorizationAuthorizingResourceType {
  #[default]
  Instance,
  Workspace,
  Project,
  User
}

#[derive(Debug, Clone, Default)]
pub struct InitialAppAuthorizationProperties {

  /// The ID of the app.
  pub app_id: Uuid,

  /// The parent resource type of the app authorization.
  pub authorizing_resource_type: AppAuthorizationAuthorizingResourceType,

  /// The ID of the parent project of the app authorization, if applicable.
  pub authorizing_project_id: Option<Uuid>,

  /// The ID of the parent workspace of the app authorization, if applicable.
  pub authorizing_workspace_id: Option<Uuid>,

  /// The ID of the parent user of the app authorization, if applicable.
  pub authorizing_user_id: Option<Uuid>

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthorization {

  /// The ID of the app authorization.
  pub id: Uuid,

  /// The ID of the app.
  pub app_id: Uuid,

  /// The parent resource type of the app authorization.
  pub authorizing_resource_type: AppAuthorizationAuthorizingResourceType,

  /// The ID of the parent project of the app authorization, if applicable.
  pub authorizing_project_id: Option<Uuid>,

  /// The ID of the parent workspace of the app authorization, if applicable.
  pub authorizing_workspace_id: Option<Uuid>,

  /// The ID of the parent user of the app authorization, if applicable.
  pub authorizing_user_id: Option<Uuid>

}

impl AppAuthorization {

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/get_app_authorization_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An app authorization with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization = Self::convert_from_row(&row);

    return Ok(app_authorization);

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppAuthorization {
      id: row.get("id"),
      app_id: row.get("app_id"),
      authorizing_resource_type: row.get("authorizing_resource_type"),
      authorizing_project_id: row.get("authorizing_project_id"),
      authorizing_workspace_id: row.get("authorizing_workspace_id"),
      authorizing_user_id: row.get("authorizing_user_id")
    };

  }

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/initialize_app_authorizations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub async fn create(initial_properties: &InitialAppAuthorizationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app_authorizations/insert_app_authorization_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.authorizing_resource_type,
      &initial_properties.authorizing_project_id,
      &initial_properties.authorizing_workspace_id,
      &initial_properties.authorizing_user_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

}

impl DeletableResource for AppAuthorization {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/delete_app_authorization_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}