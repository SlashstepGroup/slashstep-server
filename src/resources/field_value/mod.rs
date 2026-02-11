#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, StakeholderType, access_policy::IndividualPrincipal, field::FieldValueType}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "field_id",
  "parent_resource_type",
  "parent_field_id",
  "parent_item_id",
  "value_type",
  "text_value",
  "number_value",
  "boolean_value",
  "timestamp_value",
  "stakeholder_type",
  "stakeholder_user_id",
  "stakeholder_group_id",
  "stakeholder_app_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "field_id",
  "stakeholder_user_id",
  "stakeholder_group_id",
  "stakeholder_app_id",
  "parent_field_id",
  "parent_item_id"
];
pub const RESOURCE_NAME: &str = "FieldValue";
pub const DATABASE_TABLE_NAME: &str = "field_values";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.fieldValues.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "field_value_parent_resource_type")]
pub enum FieldValueParentResourceType {
  #[default]
  Field,
  Item
}

#[derive(Debug, Clone, ToSql, FromSql, Default)]
pub struct InitialFieldValueProperties {

  /// The field choice's field ID.
  pub field_id: Uuid,

  /// The field choice's parent resource type.
  pub parent_resource_type: FieldValueParentResourceType,

  /// The field choice's parent field ID, if applicable.
  pub parent_field_id: Option<Uuid>,

  /// The field choice's parent item ID, if applicable.
  pub parent_item_id: Option<Uuid>,

  /// The field choice's type.
  pub value_type: FieldValueType,

  /// The field choice's text value, if applicable.
  pub text_value: Option<String>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The field choice's boolean value, if applicable.
  pub boolean_value: Option<bool>,

  /// The field choice's date time value, if applicable.
  pub timestamp_value: Option<DateTime<Utc>>,

  /// The field choice's stakeholder type, if applicable.
  pub stakeholder_type: Option<StakeholderType>,

  /// The field choice's stakeholder user ID, if applicable.
  pub stakeholder_user_id: Option<Uuid>,

  /// The field choice's stakeholder group ID, if applicable.
  pub stakeholder_group_id: Option<Uuid>,

  /// The field choice's stakeholder app ID, if applicable.
  pub stakeholder_app_id: Option<Uuid>

}

#[derive(Debug, Clone, Serialize, Deserialize, ToSql, FromSql)]
pub struct FieldValue {

  /// The field choice's ID.
  pub id: Uuid,

  /// The field choice's field ID.
  pub field_id: Uuid,

  /// The field choice's parent resource type.
  pub parent_resource_type: FieldValueParentResourceType,

  /// The field choice's parent field ID, if applicable.
  pub parent_field_id: Option<Uuid>,

  /// The field choice's parent item ID, if applicable.
  pub parent_item_id: Option<Uuid>,

  /// The field choice's type.
  pub value_type: FieldValueType,

  /// The field choice's text value, if applicable.
  pub text_value: Option<String>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The field choice's boolean value, if applicable.
  pub boolean_value: Option<bool>,

  /// The field choice's date time value, if applicable.
  pub timestamp_value: Option<DateTime<Utc>>,

  /// The field choice's stakeholder type, if applicable.
  pub stakeholder_type: Option<StakeholderType>,

  /// The field choice's stakeholder user ID, if applicable.
  pub stakeholder_user_id: Option<Uuid>,

  /// The field choice's stakeholder group ID, if applicable.
  pub stakeholder_group_id: Option<Uuid>,

  /// The field choice's stakeholder app ID, if applicable.
  pub stakeholder_app_id: Option<Uuid>

}

impl FieldValue {

  /// Counts the number of field_values based on a query.
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
    let query = include_str!("../../queries/field_values/get_field_value_row_by_id.sql");
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

    return FieldValue {
      id: row.get("id"),
      field_id: row.get("field_id"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_field_id: row.get("parent_field_id"),
      parent_item_id: row.get("parent_item_id"),
      value_type: row.get("value_type"),
      text_value: row.get("text_value"),
      number_value: row.get("number_value"),
      boolean_value: row.get("boolean_value"),
      timestamp_value: row.get("timestamp_value"),
      stakeholder_type: row.get("stakeholder_type"),
      stakeholder_user_id: row.get("stakeholder_user_id"),
      stakeholder_group_id: row.get("stakeholder_group_id"),
      stakeholder_app_id: row.get("stakeholder_app_id")
    };

  }

  /// Initializes the field_values table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/field_values/initialize_field_values_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialFieldValueProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/field_values/insert_field_value_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.field_id,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_field_id,
      &initial_properties.parent_item_id,
      &initial_properties.value_type,
      &initial_properties.text_value,
      &initial_properties.number_value,
      &initial_properties.boolean_value,
      &initial_properties.timestamp_value,
      &initial_properties.stakeholder_type,
      &initial_properties.stakeholder_user_id,
      &initial_properties.stakeholder_group_id,
      &initial_properties.stakeholder_app_id
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

  /// Returns a list of field_values based on a query.
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

}

impl DeletableResource for FieldValue {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/field_values/delete_field_value_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}