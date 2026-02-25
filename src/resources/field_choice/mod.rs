/**
 * 
 * This module defines the implementation and types of a field choice.
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
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, StakeholderType, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "field_id",
  "description",
  "value_type",
  "text_value",
  "number_value",
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
  "stakeholder_app_id"
];
pub const RESOURCE_NAME: &str = "FieldChoice";
pub const DATABASE_TABLE_NAME: &str = "field_choices";
pub const GET_RESOURCE_ACTION_NAME: &str = "fieldChoices.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "field_choice_type")]
pub enum FieldChoiceType {
  #[default]
  Text,
  Number,
  Timestamp,
  Stakeholder
}

#[derive(Debug, Clone, ToSql, FromSql, Default)]
pub struct InitialFieldChoiceProperties {

  /// The field choice's field ID.
  pub field_id: Uuid,

  /// The field choice's description, if applicable.
  pub description: Option<String>,

  /// The field choice's type.
  pub value_type: FieldChoiceType,

  /// The field choice's text value, if applicable.
  pub text_value: Option<String>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Decimal>,

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EditableFieldChoiceProperties {

  /// The field choice's description, if applicable.
  pub description: Option<Option<String>>,

  /// The field choice's text value, if applicable.
  pub text_value: Option<Option<String>>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Option<Decimal>>,

  /// The field choice's date time value, if applicable.
  pub timestamp_value: Option<Option<DateTime<Utc>>>,

  /// The field choice's stakeholder type, if applicable.
  pub stakeholder_type: Option<Option<StakeholderType>>,

  /// The field choice's stakeholder user ID, if applicable.
  pub stakeholder_user_id: Option<Option<Uuid>>,

  /// The field choice's stakeholder group ID, if applicable.
  pub stakeholder_group_id: Option<Option<Uuid>>,

  /// The field choice's stakeholder app ID, if applicable.
  pub stakeholder_app_id: Option<Option<Uuid>>

}

#[derive(Debug, Clone, Serialize, Deserialize, ToSql, FromSql)]
pub struct FieldChoice {

  /// The field choice's ID.
  pub id: Uuid,

  /// The field choice's field ID.
  pub field_id: Uuid,

  /// The field choice's description, if applicable.
  pub description: Option<String>,

  /// The field choice's type.
  pub value_type: FieldChoiceType,

  /// The field choice's text value, if applicable.
  pub text_value: Option<String>,

  /// The field choice's number value, if applicable.
  pub number_value: Option<Decimal>,

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

impl FieldChoice {

  /// Counts the number of field_choices based on a query.
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
    let query = include_str!("../../queries/field_choices/get_field_choice_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A field choice with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return FieldChoice {
      id: row.get("id"),
      field_id: row.get("field_id"),
      description: row.get("description"),
      value_type: row.get("value_type"),
      text_value: row.get("text_value"),
      number_value: row.get("number_value"),
      timestamp_value: row.get("timestamp_value"),
      stakeholder_type: row.get("stakeholder_type"),
      stakeholder_user_id: row.get("stakeholder_user_id"),
      stakeholder_group_id: row.get("stakeholder_group_id"),
      stakeholder_app_id: row.get("stakeholder_app_id")
    };

  }

  /// Initializes the field_choices table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/field_choices/initialize_field_choices_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialFieldChoiceProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/field_choices/insert_field_choice_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.field_id,
      &initial_properties.description,
      &initial_properties.value_type,
      &initial_properties.text_value,
      &initial_properties.number_value,
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

  /// Returns a list of field_choices based on a query.
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
  pub async fn update(&self, properties: &EditableFieldChoiceProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE field_choices SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "description", properties.description.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "text_value", properties.text_value.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "number_value", properties.number_value.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "timestamp_value", properties.timestamp_value.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "stakeholder_type", properties.stakeholder_type.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "stakeholder_user_id", properties.stakeholder_user_id.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "stakeholder_group_id", properties.stakeholder_group_id.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "stakeholder_app_id", properties.stakeholder_app_id.as_ref());
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

impl DeletableResource for FieldChoice {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/field_choices/delete_field_choice_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}