use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use uuid::Uuid;

use crate::resources::ResourceError;

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone)]
#[postgres(name = "role_parent_resource_type")]
pub enum RoleParentResourceType {
  Server,
  Workspace,
  Project,
  Group
}

#[derive(Debug, Clone)]
pub struct Role {
  pub id: Uuid,
  pub name: String,
  pub is_predefined: bool,
  pub display_name: String,
  pub description: Option<String>,
  pub parent_resource_type: RoleParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_project_id: Option<Uuid>,
  pub parent_group_id: Option<Uuid>
}

#[derive(Debug, Clone)]
pub struct InitialRoleProperties {
  pub name: String,
  pub display_name: String,
  pub description: Option<String>,
  pub parent_resource_type: RoleParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_project_id: Option<Uuid>,
  pub parent_group_id: Option<Uuid>
}

impl Role {

  pub fn from_row(row: &postgres::Row) -> Self {

    return Role {
      id: row.get("id"),
      name: row.get("name"),
      is_predefined: row.get("is_predefined"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_project_id: row.get("parent_project_id"),
      parent_group_id: row.get("parent_group_id")
    };

  }

  pub async fn create(initial_properties: &InitialRoleProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/roles/insert-role-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_workspace_id,
      &initial_properties.parent_project_id,
      &initial_properties.parent_group_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError(initial_properties.name.clone()),
        
        _ => ResourceError::PostgresError(error)

      },

      None => ResourceError::PostgresError(error)

    })?;

    // Return the role.
    let role = Role::from_row(&row);

    return Ok(role);

  }

  pub async fn get_by_name(name: &str, database_pool: &deadpool_postgres::Pool) -> Result<Role, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/get-role-row-by-name.sql");
    let row = match database_client.query_opt(query, &[&name]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(name.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let role = Role::from_row(&row);

    return Ok(role);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Role, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/get-role-row-by-id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let role = Role::from_row(&row);

    return Ok(role);

  }

  /// Initializes the roles table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/initialize-roles-table.sql");
    database_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/roles/initialize-hydrated-roles-view.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}