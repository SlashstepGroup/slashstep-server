/**
 * 
 * This module defines the implementation and types of an item.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use chrono::{DateTime};
use pg_escape::{quote_literal};
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParameterType, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "summary",
  "parent_project_id",
  "number"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_project_id"
];
pub const RESOURCE_NAME: &str = "Item";
pub const DATABASE_TABLE_NAME: &str = "searchable_items";
pub const GET_RESOURCE_ACTION_NAME: &str = "items.get";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitialItemProperties {

  /// The item's summary.
  pub summary: String,

  /// The item's project ID.
  pub parent_project_id: Uuid

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EditableItemProperties {

  /// The item's summary.
  pub summary: Option<String>

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {

  /// The item's ID.
  pub id: Uuid,

  /// The item's summary.
  pub summary: String,

  /// The item's project ID.
  pub parent_project_id: Uuid,

  /// The item's number.
  pub number: i64

}

impl Item {

  /// Counts the number of items based on a query.
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
    let query = include_str!("../../queries/items/get_item_row_by_id.sql");
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

    return Item {
      id: row.get("id"),
      summary: row.get("summary"),
      parent_project_id: row.get("parent_project_id"),
      number: row.get("number")
    };

  }

  /// Initializes the items table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/items/initialize_items_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialItemProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    
    let query = include_str!("../../queries/items/insert_item_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.summary,
      &initial_properties.parent_project_id,
      &initial_properties.parent_project_id.to_string() // Number isn't included because it's auto-incremented by the database based on the project ID.
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
    let query = include_str!("../../queries/items/delete_item_row_by_id.sql");
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

    return Ok(Box::new(value));

  }

  fn translate_assignment(mut assignment_properties: SlashstepQLAssignmentProperties) -> Result<SlashstepQLAssignmentTranslationResult, SlashstepQLError> {

    // TODO: Later, this can be used for parsing in-query functions (i.e. "getCurrentUser()").

    // If the key is already a valid column in the items table, then we can directly translate the assignment without needing to account for dynamic keys.
    if ALLOWED_QUERY_KEYS.contains(&assignment_properties.key.as_str()) {

      return Ok(slashstepql::translate_normal_assignment(assignment_properties))

    }

    // Since the key is dynamic, we'll use it as a hint to form a valid SQL query.
    let identifier_parts = (&assignment_properties.key).split('.').collect::<Vec<&str>>();
    match identifier_parts[0] {

      "fields" => {

        // In this case, the identifier should be made of two parts: the "fields" prefix and the field name. For example, "fields.priority".
        if identifier_parts.len() != 2 {

          return Err(SlashstepQLError::InvalidFieldError(assignment_properties.key));

        }

        // Since the filter lacks the field value type and only includes the field name, we have to check the value against all possible field value types.
        // 
        // The filter may be queried on multiple levels. For example, "/items?query=fields.priority = 'High'" targets all items across the server and searches for any fields named "priority". 
        // In one project, the ID may be `00000000-0000-0000-0000-000000000000` and in another project, the ID may be `11111111-1111-1111-1111-111111111111`; 
        // but, they both have the same field name of "priority" and must be accounted for.
        // 
        // TODO: Can we turn this query into a view to improve readability?
        let field_name = identifier_parts[1];
        assignment_properties.where_clause.push_str(&format!("((SELECT COUNT(*) FROM searchable_items searchable_items_subquery LEFT JOIN fields ON fields.parent_project_id = searchable_items.parent_project_id LEFT JOIN field_values ON field_values.field_id = fields.id WHERE fields.name = {} AND searchable_items.id = searchable_items_subquery.id AND (SELECT COUNT(*) FROM field_values WHERE (field_values.parent_item_id = searchable_items.id OR field_values.parent_field_id = fields.id)", quote_literal(field_name)));
        
        if let Some(string_value) = assignment_properties.string_value {

          assignment_properties.where_clause.push_str(" AND (");

          if let Ok(uuid_value) = Uuid::parse_str(&string_value) {

            // UUID field types: Iteration, Milestone, Stakeholder

            // UUIDs are supposed to be globally unique, so it's generally safe to check the ID against all UUID columns.
            let uuid_column_name_map = vec![
              vec!["Iteration", "iteration_id_value"],
              vec!["Milestone", "milestone_id_value"],
              vec!["Stakeholder", "stakeholder_user_id"],
              vec!["Stakeholder", "stakeholder_group_id"],
              vec!["Stakeholder", "stakeholder_app_id"]
            ];

            for index in 0..uuid_column_name_map.len() {

              if index != 0 {

                assignment_properties.where_clause.push_str(" OR ");

              }

              let value_type = uuid_column_name_map[index][0];
              let column_name = uuid_column_name_map[index][1];
              assignment_properties.where_clause.push_str(&format!("(field_values.value_type = {} AND field_values.{} {} ${})", quote_literal(value_type), column_name, &assignment_properties.operator, assignment_properties.parameters.len() + 1));
              assignment_properties.parameters.push((assignment_properties.key.clone(), SlashstepQLParameterType::UUID(uuid_value)));

            }

            assignment_properties.where_clause.push_str(" OR ")

          } else if let Ok(datetime_value) = DateTime::parse_from_rfc3339(&string_value) {

            assignment_properties.where_clause.push_str(&format!("(field_values.value_type = 'Timestamp' AND field_values.timestamp_value {} ${})", &assignment_properties.operator, assignment_properties.parameters.len() + 1));
            assignment_properties.parameters.push((assignment_properties.key.clone(), SlashstepQLParameterType::Timestamp(datetime_value)));
            assignment_properties.where_clause.push_str(" OR ")

          }

          // Despite the text value may being a UUID or a date, there's a chance that field value type might just be normal text.
          // So, we have to account for that as well.
          assignment_properties.where_clause.push_str(&format!("(field_values.value_type = 'Text' AND field_values.text_value {} ${})", &assignment_properties.operator, assignment_properties.parameters.len() + 1));
          assignment_properties.where_clause.push_str(")) = 1");
          assignment_properties.parameters.push((assignment_properties.key.clone(), SlashstepQLParameterType::String(string_value.clone())));

        } else if let Some(number_value) = assignment_properties.number_value {

          assignment_properties.where_clause.push_str(&format!(" AND (field_values.value_type = 'Number' AND field_values.number_value {} ${})) = 1", &assignment_properties.operator, assignment_properties.parameters.len() + 1));
          assignment_properties.parameters.push((assignment_properties.key.clone(), SlashstepQLParameterType::Number(number_value)));

        } else if let Some(boolean_value) = assignment_properties.boolean_value {

          assignment_properties.where_clause.push_str(&format!(" AND (field_values.value_type = 'Boolean' AND field_values.boolean_value {} ${})) = 1", &assignment_properties.operator, assignment_properties.parameters.len() + 1));
          assignment_properties.parameters.push((assignment_properties.key.clone(), SlashstepQLParameterType::Boolean(boolean_value)));

        }

        assignment_properties.where_clause.push_str(") = 1)");

      },

      _ => return Err(SlashstepQLError::InvalidFieldError(assignment_properties.key))

    }

    let assignment_translation_result = SlashstepQLAssignmentTranslationResult {
      where_clause: assignment_properties.where_clause,
      parameters: assignment_properties.parameters
    };

    return Ok(assignment_translation_result);

  }

  /// Returns a list of items based on a query.
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

  /// Updates this item and returns a new instance of the item.
  pub async fn update(&self, properties: &EditableItemProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE items SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "summary", properties.summary.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let item = Self::convert_from_row(&row);
    return Ok(item);

  }

}
