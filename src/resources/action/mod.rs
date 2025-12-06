/**
 * 
 * This module defines the implementation and types of an action.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use postgres::error::SqlState;
use postgres_types::ToSql;
use thiserror::Error;
use uuid::Uuid;

pub struct Action {

  /// The action's ID.
  pub id: Uuid,

  /// The action's name.
  pub name: String,

  /// The action's display name.
  pub display_name: String,

  /// The action's description.
  pub description: String,

  /// The action's app ID, if applicable. Actions without an app ID are global actions.
  pub app_id: Option<Uuid>

}

pub struct InitialActionProperties {

  /// The action's name.
  pub name: String,

  /// The action's display name.
  pub display_name: String,

  /// The action's description.
  pub description: String,

  /// The action's app ID, if applicable. Actions without an app ID are global actions.
  pub app_id: Option<Uuid>

}

#[derive(Debug, Error)]
pub enum ActionError {
  #[error("An action with the name \"{0}\" already exists.")]
  ConflictError(String),

  #[error("Couldn't find an action with the name \"{0}\".")]
  NotFoundError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

impl Action {

  pub fn from_row(row: &postgres::Row) -> Self {

    return Action {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      app_id: row.get("app_id")
    };

  }

  /// Creates a new action.
  pub async fn create(initial_properties: &InitialActionProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ActionError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/actions/insert-action-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.app_id
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => {

        match db_error.code() {

          &SqlState::UNIQUE_VIOLATION => ActionError::ConflictError(initial_properties.name.clone()),
          
          _ => ActionError::PostgresError(error)

        }

      },

      None => ActionError::PostgresError(error)
    
    })?;

    // Return the action.
    let action = Action::from_row(&row);

    return Ok(action);

  }

  pub async fn get_by_name(name: &str, postgres_client: &mut deadpool_postgres::Client) -> Result<Action, ActionError> {

    let query = include_str!("../../queries/actions/get-action-row-by-name.sql");
    let row = match postgres_client.query_opt(query, &[&name]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ActionError::NotFoundError(name.to_string()))

      },

      Err(error) => return Err(ActionError::PostgresError(error))

    };

    let action = Action::from_row(&row);

    return Ok(action);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ActionError> {

    let query = include_str!("../../queries/actions/get-action-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ActionError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ActionError::PostgresError(error))

    };

    let action = Action::from_row(&row);

    return Ok(action);

  }

  /// Initializes the actions table.
  pub async fn initialize_actions_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), ActionError> {

    let table_initialization_query = include_str!("../../queries/actions/initialize-actions-table.sql");
    postgres_client.execute(table_initialization_query, &[]).await?;

    let view_initialization_query = include_str!("../../queries/actions/initialize-hydrated-actions-view.sql");
    postgres_client.execute(view_initialization_query, &[]).await?;

    return Ok(());

  }

}

#[cfg(test)]
mod tests;