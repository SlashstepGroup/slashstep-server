use postgres::error::SqlState;
use postgres_types::ToSql;
use uuid::Uuid;
use crate::{errors::resource_already_exists_error::ResourceAlreadyExistsError};

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

#[derive(Debug)]
pub enum ActionCreationError<'a> {
  ResourceAlreadyExistsError(ResourceAlreadyExistsError<'a>),
  String(String),
  PostgresError(postgres::Error)
}

impl Action {

  /// Creates a new action.
  pub fn create<'a>(initial_properties: &'a InitialActionProperties, postgres_client: &mut postgres::Client) -> Result<Self, ActionCreationError<'a>> {

    // Insert the access policy into the database.
    let query = include_str!("../queries/actions/insert-action-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.app_id
    ];
    let rows = postgres_client.query(query, parameters);

    // Return the action.
    match rows {

      Ok(rows) => {

        let row = rows.get(0).ok_or(ActionCreationError::String("Client did not return a row.".to_string()))?;
        let action = Action {
          id: row.get("id"),
          name: row.get("name"),
          display_name: row.get("display_name"),
          description: row.get("description"),
          app_id: row.get("app_id")
        };

        return Ok(action);
        
      },

      Err(error) => match error.as_db_error() {

        Some(db_error) => {

          let error_code = db_error.code();
          match error_code {

            &SqlState::UNIQUE_VIOLATION => {

              let resource_already_exists_error = ResourceAlreadyExistsError {
                resource_type: "Action"
              };

              Err(ActionCreationError::ResourceAlreadyExistsError(resource_already_exists_error))

            },
            
            _ => {
              Err(ActionCreationError::PostgresError(error))
            }

          }

        },

        None => {

          Err(ActionCreationError::PostgresError(error))

        }

      }

    }

  }

  /// Initializes the actions table.
  pub fn initialize_actions_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/actions/initialize-actions-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}