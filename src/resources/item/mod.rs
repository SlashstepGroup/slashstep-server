use postgres::error::SqlState;
use postgres_types::ToSql;
use serde::Serialize;
use uuid::Uuid;

use crate::resources::ResourceError;

pub struct InitialItemProperties<'a> {
  pub summary: &'a str,
  pub description: &'a str,
  pub project_id: Uuid,
  pub number: i64
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
  pub id: Uuid,
  pub summary: String,
  pub description: String,
  pub project_id: Uuid,
  pub number: i64
}

impl Item {

  pub fn from_row(row: &postgres::Row) -> Self {

    return Item {
      id: row.get("id"),
      summary: row.get("summary"),
      description: row.get("description"),
      project_id: row.get("project_id"),
      number: row.get("number")
    };

  }

  pub async fn create(initial_properties: &InitialItemProperties<'_>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/items/insert-item-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.summary,
      &initial_properties.description,
      &initial_properties.project_id,
      &initial_properties.number
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError(initial_properties.summary.to_string()),
        
        _ => ResourceError::PostgresError(error)

      },

      None => ResourceError::PostgresError(error)

    })?;

    // Return the item.
    let item = Item::from_row(&row);

    return Ok(item);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/items/get-item-row-by-id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let item = Item::from_row(&row);

    return Ok(item);

  }
  
  /// Initializes the items table.
  pub async fn initialize_items_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/items/initialize-items-table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}