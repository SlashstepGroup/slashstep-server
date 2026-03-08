/**
 * 
 * This module defines the implementation and types of a status.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::str::FromStr;

use postgres::error::SqlState;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_view_id",
  "field_id",
  "next_status_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_view_id",
  "next_status_id"
];
pub const RESOURCE_NAME: &str = "Status";
pub const DATABASE_TABLE_NAME: &str = "statuses";
pub const GET_RESOURCE_ACTION_NAME: &str = "statuses.get";

#[derive(Debug, Clone, Copy, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "status_type")]
pub enum StatusType {
  
  /// A status that represents a "to do" item.
  #[default]
  ToDo,

  /// A status that represents an "in progress" item.
  InProgress,

  /// A status that represents a "done" item.
  Done

}

impl FromStr for StatusType {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {

      "ToDo" => Ok(Self::ToDo),
      "InProgress" => Ok(Self::InProgress),
      "Done" => Ok(Self::Done),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))

    }

  }

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InitialStatusProperties {

  /// The status's display name.
  pub display_name: String,

  /// The status's status type.
  pub status_type: StatusType,

  /// The status's decimal color, if applicable. If not provided, clients should provide a default color.
  pub decimal_color: Option<i32>,

  /// The status's description, if applicable.
  pub description: Option<String>,

  /// The status's next status ID, if applicable. 
  /// 
  /// This is the next status in the list. If not provided, one can assume that this status is at the end of the list.
  pub next_status_id: Option<Uuid>,

  /// The status's parent project ID.
  pub parent_project_id: Uuid

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EditableStatusProperties {

  /// The status's display name.
  pub display_name: Option<String>,

  /// The status's status type.
  pub status_type: Option<StatusType>,

  /// The status's decimal color, if applicable. If not provided, clients should provide a default color.
  pub decimal_color: Option<Option<i32>>,

  /// The status's description, if applicable.
  pub description: Option<Option<String>>,

  /// The status's next status ID, if applicable. 
  /// 
  /// This is the next status in the list. If not provided, one can assume that this status is at the end of the list.
  pub next_status_id: Option<Option<Uuid>>

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {

  /// The status's ID.
  pub id: Uuid,

  /// The status's display name.
  pub display_name: String,

  /// The status's status type.
  pub status_type: StatusType,

  /// The status's decimal color, if applicable. If not provided, clients should provide a default color.
  pub decimal_color: Option<i32>,

  /// The status's description, if applicable.
  pub description: Option<String>,

  /// The status's next status ID, if applicable. 
  /// 
  /// This is the next status in the list. If not provided, one can assume that this status is at the end of the list.
  pub next_status_id: Option<Uuid>,

  /// The status's parent project ID.
  pub parent_project_id: Uuid

}

impl Status {

  /// Counts the number of statuses based on a query.
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<i64, ResourceError> {

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
    let database_client = database_pool.get().await?;
    let get_resource_action_id: Uuid = database_client.query_one("SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'", &[&GET_RESOURCE_ACTION_NAME]).await?.get(0);
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &get_resource_action_id, true)?;
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Gets a field by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/statuses/get_status_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A field value with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Self {
      id: row.get("id"),
      display_name: row.get("display_name"),
      status_type: row.get("status_type"),
      decimal_color: row.get("decimal_color"),
      description: row.get("description"),
      next_status_id: row.get("next_status_id"),
      parent_project_id: row.get("parent_project_id")
    };

  }

  /// Initializes the statuses table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/statuses/initialize_statuses_table.sql");
    database_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/statuses/create_function_verify_next_status_parent_project_id.sql");
    database_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/statuses/create_function_update_statuses_next_status_id.sql");
    database_client.execute(query, &[]).await?;

    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialStatusProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/statuses/insert_status_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.display_name,
      &initial_properties.status_type,
      &initial_properties.decimal_color,
      &initial_properties.description,
      &initial_properties.next_status_id,
      &initial_properties.parent_project_id
    ];
    let database_client = database_pool.get().await?;
    let row = match database_client.query_one(query, parameters).await {

      Ok(row) => row,

      Err(error) => match error.as_db_error() {

        Some(db_error) => match db_error.code() {

          &SqlState::RAISE_EXCEPTION => match db_error.message() {

            "Next statuses must belong to the same parent project." => return Err(ResourceError::DifferentParentError("next_status_id".to_string())),

            _ => return Err(ResourceError::PostgresError(error))

          },

          _ => return Err(ResourceError::PostgresError(error))

        },

        None => return Err(ResourceError::PostgresError(error))

      }

    };

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

  /// Deletes this field.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/statuses/delete_status_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Parses a string into a parameter for a slashstepql query.
  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    match key {

      "status_type" => {

        let scoped_resource_type = match StatusType::from_str(value) {

          Ok(scoped_resource_type) => scoped_resource_type,
          Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\": {}", value, key, error)))

        };

        return Ok(Box::new(scoped_resource_type));

      },

      _ => {}

    }

    return Ok(Box::new(value));

  }

  /// Returns a list of statuses based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let database_client = database_pool.get().await?;
    let get_resource_action_id: Uuid = database_client.query_one("SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'", &[&GET_RESOURCE_ACTION_NAME]).await?.get(0);
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, principal_type, principal_id, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &get_resource_action_id, false)?;
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let rows = database_client.query(&query, &parameters).await?;
    let actions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(actions);

  }

  /// Updates this item and returns a new instance of the item.
  pub async fn update(&self, properties: &EditableStatusProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE statuses SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", properties.display_name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "status_type", properties.status_type.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "decimal_color", properties.decimal_color.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "description", properties.description.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "next_status_id", properties.next_status_id.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let status = Self::convert_from_row(&row);
    return Ok(status);

  }

}
