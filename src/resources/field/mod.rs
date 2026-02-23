#[cfg(test)]
mod tests;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "display_name",
  "description",
  "is_required",
  "type",
  "minimum_value",
  "maximum_value",
  "minimum_choice_count",
  "maximum_choice_count",
  "parent_resource_type",
  "parent_project_id",
  "parent_workspace_id",
  "parent_user_id",
  "is_deadline"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_project_id",
  "parent_workspace_id",
  "parent_user_id"
];
pub const RESOURCE_NAME: &str = "Field";
pub const DATABASE_TABLE_NAME: &str = "fields";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.fields.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "field_value_type")]
pub enum FieldValueType {
  #[default]
  Text,
  Number,
  Boolean,
  Timestamp,
  Stakeholder
}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "field_parent_resource_type")]
pub enum FieldParentResourceType {
  #[default]
  Project,
  Workspace
}

#[derive(Debug, Clone, ToSql, FromSql, Default)]
pub struct InitialFieldProperties {

  /// The field's name.
  pub name: String,

  /// The field's display name.
  pub display_name: String,

  /// The field's description.
  pub description: String,

  /// Whether the field is required.
  pub is_required: bool,

  /// The field's type.
  pub field_value_type: FieldValueType,

  /// The field's minimum value.
  pub minimum_value: Option<Decimal>,

  /// The field's maximum value.
  pub maximum_value: Option<Decimal>,

  /// The field's minimum choice count.
  pub minimum_choice_count: Option<i32>,

  /// The field's maximum choice count.
  pub maximum_choice_count: Option<i32>,

  /// The field's parent resource type.
  pub parent_resource_type: FieldParentResourceType,

  /// The field's parent project ID.
  pub parent_project_id: Option<Uuid>,

  /// The field's parent workspace ID.
  pub parent_workspace_id: Option<Uuid>,

  /// Whether the field is a deadline.
  pub is_deadline: Option<bool>

}

#[derive(Debug, Clone, Serialize, Deserialize, ToSql, FromSql, Default)]
pub struct EditableFieldProperties {

  /// The field's name.
  pub name: Option<String>,

  /// The field's display name.
  pub display_name: Option<String>,

  /// The field's description.
  pub description: Option<String>,

  /// Whether the field is required.
  pub is_required: Option<bool>,

  /// The field's minimum value.
  pub minimum_value: Option<Option<Decimal>>,

  /// The field's maximum value.
  pub maximum_value: Option<Option<Decimal>>,

  /// The field's minimum choice count.
  pub minimum_choice_count: Option<Option<i32>>,

  /// The field's maximum choice count.
  pub maximum_choice_count: Option<Option<i32>>,

  /// Whether the field is a deadline.
  pub is_deadline: Option<Option<bool>>

}

#[derive(Debug, Clone, Serialize, Deserialize, ToSql, FromSql)]
pub struct Field {

  /// The field's ID.
  pub id: Uuid,

  /// The field's name.
  pub name: String,

  /// The field's display name.
  pub display_name: String,

  /// The field's description.
  pub description: String,

  /// Whether the field is required.
  pub is_required: bool,

  /// The field's type.
  pub field_value_type: FieldValueType,

  /// The field's minimum value.
  pub minimum_value: Option<Decimal>,

  /// The field's maximum value.
  pub maximum_value: Option<Decimal>,

  /// The field's minimum choice count.
  pub minimum_choice_count: Option<i32>,

  /// The field's maximum choice count.
  pub maximum_choice_count: Option<i32>,

  /// The field's parent resource type.
  pub parent_resource_type: FieldParentResourceType,

  /// The field's parent project ID.
  pub parent_project_id: Option<Uuid>,

  /// The field's parent workspace ID.
  pub parent_workspace_id: Option<Uuid>,

  /// Whether the field is a deadline.
  pub is_deadline: Option<bool>

}

impl Field {

  /// Counts the number of fields based on a query.
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, ResourceError> {

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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let database_client = database_pool.get().await?;
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Gets a field by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/fields/get_field_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An field with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Field {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      is_required: row.get("is_required"),
      field_value_type: row.get("type"),
      minimum_value: row.get("minimum_value"),
      maximum_value: row.get("maximum_value"),
      minimum_choice_count: row.get("minimum_choice_count"),
      maximum_choice_count: row.get("maximum_choice_count"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_project_id: row.get("parent_project_id"),
      parent_workspace_id: row.get("parent_workspace_id"),
      is_deadline: row.get("is_deadline")
    };

  }

  /// Initializes the fields table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/fields/initialize_fields_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialFieldProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/fields/insert_field_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.is_required,
      &initial_properties.field_value_type,
      &initial_properties.minimum_value,
      &initial_properties.maximum_value,
      &initial_properties.minimum_choice_count,
      &initial_properties.maximum_choice_count,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_project_id,
      &initial_properties.parent_workspace_id,
      &initial_properties.is_deadline
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

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

  /// Returns a list of fields based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

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
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let actions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(actions);

  }

  /// Updates this field and returns a new instance of the field.
  pub async fn update(&self, properties: &EditableFieldProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE fields SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "name", properties.name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", properties.display_name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "description", properties.description.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "is_required", properties.is_required.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "minimum_value", properties.minimum_value.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "maximum_value", properties.maximum_value.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "minimum_choice_count", properties.minimum_choice_count.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "maximum_choice_count", properties.maximum_choice_count.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "is_deadline", properties.is_deadline.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let configuration = Self::convert_from_row(&row);
    return Ok(configuration);

  }

}

impl DeletableResource for Field {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/fields/delete_field_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}