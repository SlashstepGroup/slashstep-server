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
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use crate::{resources::access_policy::IndividualPrincipal, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_ACTION_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_ACTION_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "display_name",
  "description",
  "app_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "app_id"
];

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
#[postgres(name = "action_parent_resource_type")]
pub enum ActionParentResourceType {
  Instance,
  App
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
  pub app_id: Option<Uuid>,

  /// The action's parent resource type.
  pub parent_resource_type: ActionParentResourceType

}

pub struct InitialActionProperties {

  /// The action's name.
  pub name: String,

  /// The action's display name.
  pub display_name: String,

  /// The action's description.
  pub description: String,

  /// The action's app ID, if applicable. Actions without an app ID are global actions.
  pub app_id: Option<Uuid>,

  /// The action's parent resource type.
  pub parent_resource_type: ActionParentResourceType

}

/// A repreentation of editable action properties.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditableActionProperties {

  /// The action's name.
  pub name: Option<String>,

  /// The action's display name.
  pub display_name: Option<String>,

  /// The action's description.
  pub description: Option<String>

}

#[derive(Debug, Error)]
pub enum ActionError {
  #[error("An action with the name \"{0}\" already exists.")]
  ConflictError(String),

  #[error("Couldn't find an action with the name \"{0}\".")]
  NotFoundError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  SlashstepQLError(#[from] SlashstepQLError)
}

impl Action {

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: &Option<T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    if let Some(parameter_value) = parameter_value.clone() {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return Action {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      app_id: row.get("app_id"),
      parent_resource_type: row.get("parent_resource_type")
    };

  }

  pub async fn count(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, ActionError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: None,
      maximum_limit: None,
      should_ignore_limit: true,
      should_ignore_offset: true
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "Action", "actions", "slashstep.actions.get", true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let rows = postgres_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new action.
  pub async fn create(initial_properties: &InitialActionProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ActionError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/actions/insert-action-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.app_id,
      &initial_properties.parent_resource_type
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
    let action = Action::convert_from_row(&row);

    return Ok(action);

  }

  pub async fn delete(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<(), ActionError> {

    let query = include_str!("../../queries/actions/delete-action-row.sql");
    postgres_client.execute(query, &[&self.id]).await?;
    return Ok(());

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

    let action = Action::convert_from_row(&row);

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

    let action = Action::convert_from_row(&row);

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

  /// Returns a list of actions based on a query.
  pub async fn list(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ActionError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ACTION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_ACTION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, "Action", "actions", "slashstep.actions.get", false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let rows = postgres_client.query(&query, &parameters).await?;
    let actions = rows.iter().map(Action::convert_from_row).collect();
    return Ok(actions);

  }

  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    return Ok(Box::new(value));

  }

  /// Updates this action and returns a new instance of the action.
  pub async fn update(&self, properties: &EditableActionProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ActionError> {

    let query = String::from("UPDATE actions SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

    postgres_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "name", &properties.name);
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "display_name", &properties.display_name);
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "description", &properties.description);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = postgres_client.query_one(&query, &parameters).await?;
    postgres_client.query("COMMIT;", &[]).await?;

    let access_policy = Action::convert_from_row(&row);
    return Ok(access_policy);

  }

}

#[cfg(test)]
mod tests;