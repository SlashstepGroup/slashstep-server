/**
 * 
 * This module defines the implementation and types of an action.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 – 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_ACTION_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "display_name",
  "description",
  "parent_app_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_app_id"
];
pub const GET_RESOURCE_ACTION_NAME: &str = "actions.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "action_parent_resource_type")]
pub enum ActionParentResourceType {
  #[default]
  Server,
  App
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialActionPropertiesForPredefinedScope {

  /// The action's name.
  pub name: String,

  /// The action's display name.
  pub display_name: String,

  /// The action's description.
  pub description: String

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
  pub parent_app_id: Option<Uuid>,

  /// The action's parent resource type.
  pub parent_resource_type: ActionParentResourceType

}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InitialActionProperties {

  /// The action's name.
  pub name: String,

  /// The action's display name.
  pub display_name: String,

  /// The action's description.
  pub description: String,

  /// The action's app ID, if applicable. Actions without an app ID are global actions.
  pub parent_app_id: Option<Uuid>,

  /// The action's parent resource type.
  pub parent_resource_type: ActionParentResourceType

}

/// A repreentation of editable action properties.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EditableActionProperties {

  /// The action's name.
  pub name: Option<String>,

  /// The action's display name.
  pub display_name: Option<String>,

  /// The action's description.
  pub description: Option<String>

}

impl Action {

  fn convert_from_row(row: &postgres::Row) -> Self {

    return Action {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      parent_app_id: row.get("parent_app_id"),
      parent_resource_type: row.get("parent_resource_type")
    };

  }

  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<i64, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      default_limit: None,
      maximum_limit: None,
      should_ignore_limit: true,
      should_ignore_offset: true,
      translate_assignment: Self::translate_assignment
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let database_client = database_pool.get().await?;
    let get_resource_action_id: Uuid = database_client.query_one("SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'", &[&GET_RESOURCE_ACTION_NAME]).await?.get(0);
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, "Action", "actions", &get_resource_action_id, true)?;
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Creates a new action.
  pub async fn create(initial_properties: &InitialActionProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    // Insert the access policy into the database.
    let query = include_str!("../../queries/actions/insert_action_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.parent_app_id,
      &initial_properties.parent_resource_type
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => {

        match db_error.code() {

          &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError("An action with the same name already exists.".to_string()),
          
          _ => ResourceError::PostgresError(error)

        }

      },

      None => ResourceError::PostgresError(error)
    
    })?;

    // Return the action.
    let action = Action::convert_from_row(&row);

    return Ok(action);

  }

  /// Deletes this action.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/actions/delete_action_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  pub async fn get_by_name(name: &str, database_pool: &deadpool_postgres::Pool) -> Result<Action, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/actions/get_action_row_by_name.sql");
    let row = match database_client.query_opt(query, &[&name]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(name.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let action = Action::convert_from_row(&row);

    return Ok(action);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/actions/get_action_row_by_id.sql");
    let database_client = database_pool.get().await?;
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let action = Action::convert_from_row(&row);

    return Ok(action);

  }

  /// Initializes the actions table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let table_initialization_query = include_str!("../../queries/actions/initialize_actions_table.sql");
    database_client.execute(table_initialization_query, &[]).await?;

    return Ok(());

  }

  /// Returns a list of actions based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      default_limit: Some(DEFAULT_ACTION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false,
      translate_assignment: Self::translate_assignment
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let database_client = database_pool.get().await?;
    let get_resource_action_id: Uuid = database_client.query_one("SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'", &[&GET_RESOURCE_ACTION_NAME]).await?.get(0);
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, "Action", "actions", &get_resource_action_id, false)?;
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let rows = database_client.query(&query, &parameters).await?;
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

  fn translate_assignment(mut assignment_properties: SlashstepQLAssignmentProperties) -> Result<SlashstepQLAssignmentTranslationResult, SlashstepQLError> {

    // TODO: Later, this can be used for parsing in-query functions (i.e. "getCurrentUser()").

    // If the key is already a valid column in the items table, then we can directly translate the assignment without needing to account for dynamic keys.
    if ALLOWED_QUERY_KEYS.contains(&assignment_properties.key.as_str()) {

      return Ok(slashstepql::translate_normal_assignment(assignment_properties))

    }

    return Err(SlashstepQLError::InvalidFieldError(assignment_properties.key));

  }

  /// Updates this action and returns a new instance of the action.
  pub async fn update(&self, properties: &EditableActionProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE actions SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "name", Some(&properties.name));
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", Some(&properties.display_name));
    let (mut parameter_boxes, mut query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "description", Some(&properties.description));

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let access_policy = Action::convert_from_row(&row);
    return Ok(access_policy);

  }

}
