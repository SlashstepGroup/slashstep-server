/**
 * 
 * This module defines the implementation and types of an iteration.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_project_id",
  "display_name",
  "start_date",
  "end_date",
  "actual_start_date",
  "actual_end_date"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_project_id",
];
pub const RESOURCE_NAME: &str = "Iteration";
pub const DATABASE_TABLE_NAME: &str = "iterations";
pub const GET_RESOURCE_ACTION_NAME: &str = "iterations.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InitialIterationProperties {

  /// The iteration's parent project ID.
  pub parent_project_id: Uuid,

  /// The iteration's display name.
  pub display_name: String,

  /// The iteration's start date.
  pub start_date: DateTime<Utc>,

  /// The iteration's end date.
  pub end_date: DateTime<Utc>,

  /// The iteration's actual start date, if applicable.
  pub actual_start_date: Option<DateTime<Utc>>,

  /// The iteration's actual end date, if applicable.
  pub actual_end_date: Option<DateTime<Utc>>

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EditableIterationProperties {

  /// The iteration's display name.
  pub display_name: Option<String>,

  /// The iteration's start date.
  pub start_date: Option<DateTime<Utc>>,

  /// The iteration's end date.
  pub end_date: Option<DateTime<Utc>>,

  /// The iteration's actual start date, if applicable.
  pub actual_start_date: Option<Option<DateTime<Utc>>>,

  /// The iteration's actual end date, if applicable.
  pub actual_end_date: Option<Option<DateTime<Utc>>>,

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct Iteration {

  /// The iteration's ID.
  pub id: Uuid,

  /// The iteration's parent project ID.
  pub parent_project_id: Uuid,

  /// The iteration's display name.
  pub display_name: String,

  /// The iteration's start date.
  pub start_date: DateTime<Utc>,

  /// The iteration's end date.
  pub end_date: DateTime<Utc>,

  /// The iteration's actual start date, if applicable.
  pub actual_start_date: Option<DateTime<Utc>>,

  /// The iteration's actual end date, if applicable.
  pub actual_end_date: Option<DateTime<Utc>>

}

impl Iteration {

  /// Counts the number of iterations based on a query.
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
    let query = include_str!("../../queries/iterations/get_iteration_row_by_id.sql");
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
      parent_project_id: row.get("parent_project_id"),
      display_name: row.get("display_name"),
      start_date: row.get("start_date"),
      end_date: row.get("end_date"),
      actual_start_date: row.get("actual_start_date"),
      actual_end_date: row.get("actual_end_date")
    };

  }

  /// Initializes the iterations table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/iterations/initialize_iterations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialIterationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/iterations/insert_iteration_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.parent_project_id,
      &initial_properties.display_name,
      &DateTime::from_timestamp_millis(initial_properties.start_date.timestamp_millis()),
      &DateTime::from_timestamp_millis(initial_properties.end_date.timestamp_millis()),
      &initial_properties.actual_start_date.map(|date| DateTime::from_timestamp_millis(date.timestamp_millis())),
      &initial_properties.actual_end_date.map(|date| DateTime::from_timestamp_millis(date.timestamp_millis()))
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

  /// Deletes this field.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/iterations/delete_iteration_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Returns a list of iterations based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false,
      translate_assignment: Self::translate_assignment
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

  /// Parses a string into a parameter for a slashstepql query.
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

  fn translate_assignment(assignment_properties: SlashstepQLAssignmentProperties) -> Result<SlashstepQLAssignmentTranslationResult, SlashstepQLError> {

    // TODO: Later, this can be used for parsing in-query functions (i.e. "getCurrentUser()").

    // If the key is already a valid column in the items table, then we can directly translate the assignment without needing to account for dynamic keys.
    if ALLOWED_QUERY_KEYS.contains(&assignment_properties.key.as_str()) {

      return Ok(slashstepql::translate_normal_assignment(assignment_properties))

    }

    return Err(SlashstepQLError::InvalidFieldError(assignment_properties.key));

  }

  /// Updates this item and returns a new instance of the item.
  pub async fn update(&self, properties: &EditableIterationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE iterations SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", properties.display_name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "start_date", properties.start_date.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "end_date", properties.end_date.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "actual_start_date", properties.actual_start_date.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "actual_end_date", properties.actual_end_date.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let iteration = Self::convert_from_row(&row);
    return Ok(iteration);

  }

}
