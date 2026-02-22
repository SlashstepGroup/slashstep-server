#[cfg(test)]
mod tests;

use std::str::FromStr;

use postgres_types::{FromSql, ToSql};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "description",
  "value_type"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id"
];
pub const RESOURCE_NAME: &str = "Configuration";
pub const DATABASE_TABLE_NAME: &str = "configurations";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.configurations.get";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, ToSql, FromSql, EnumIter)]
#[postgres(name = "configuration_value_type")]
pub enum ConfigurationValueType {
  #[default]
  Text,
  Number,
  Boolean
}

impl FromStr for ConfigurationValueType {

  type Err = ResourceError;

  fn from_str(input: &str) -> Result<ConfigurationValueType, Self::Err> {

    match input {

      "Text" => Ok(ConfigurationValueType::Text),
      "Number" => Ok(ConfigurationValueType::Number),
      "Boolean" => Ok(ConfigurationValueType::Boolean),
      _ => Err(ResourceError::UnexpectedEnumVariantError(input.to_string()))

    }

  }

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InitialConfigurationProperties {

  /// The configuration's name.
  pub name: String,

  /// The configuration's description, if applicable.
  pub description: Option<String>,

  /// The configuration's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>,

  /// The configuration's default text value, if applicable.
  pub default_text_value: Option<String>,

  /// The configuration's default number value, if applicable.
  pub default_number_value: Option<Decimal>,

  /// The configuration's default boolean value, if applicable.
  pub default_boolean_value: Option<bool>

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EditableConfigurationProperties {

  /// The configuration's name.
  pub name: Option<String>,

  /// The configuration's description, if applicable.
  pub description: Option<String>,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>,

  /// The configuration's default text value, if applicable.
  pub default_text_value: Option<String>,

  /// The configuration's default number value, if applicable.
  pub default_number_value: Option<Decimal>,

  /// The configuration's default boolean value, if applicable.
  pub default_boolean_value: Option<bool>

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Configuration {

  /// The configuration's ID.
  pub id: Uuid,
  
  /// The configuration's name.
  pub name: String,

  /// The configuration's description, if applicable.
  pub description: Option<String>,

  /// The configuration's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>,

  /// The configuration's default text value, if applicable.
  pub default_text_value: Option<String>,

  /// The configuration's default number value, if applicable.
  pub default_number_value: Option<Decimal>,

  /// The configuration's default boolean value, if applicable.
  pub default_boolean_value: Option<bool>

}

impl Configuration {

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: Option<&T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    let parameter_value = parameter_value.and_then(|parameter_value| Some(parameter_value.clone()));
    if let Some(parameter_value) = parameter_value {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }
  
  /// Counts the number of configurations based on a query.
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

  /// Gets a configuration by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configurations/get_configuration_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A configuration with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let configuration = Self::convert_from_row(&row);

    return Ok(configuration);

  }

  pub async fn get_by_name(name: &str, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configurations/get_configuration_row_by_name.sql");
    let row = match database_client.query_opt(query, &[&name]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A configuration with the name \"{}\" does not exist.", name)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let configuration = Self::convert_from_row(&row);

    return Ok(configuration);

  }

  /// Converts a row into a configuration.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Configuration {
      id: row.get("id"),
      name: row.get("name"),
      description: row.get("description"),
      value_type: row.get("value_type"),
      text_value: row.get("text_value"),
      number_value: row.get("number_value"),
      boolean_value: row.get("boolean_value"),
      default_text_value: row.get("default_text_value"),
      default_number_value: row.get("default_number_value"),
      default_boolean_value: row.get("default_boolean_value")
    };

  }

  /// Initializes the configurations table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configurations/initialize_configurations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new configuration.
  pub async fn create(initial_properties: &InitialConfigurationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    
    let query = include_str!("../../queries/configurations/insert_configuration_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.description,
      &initial_properties.value_type,
      &initial_properties.text_value,
      &initial_properties.number_value,
      &initial_properties.boolean_value,
      &initial_properties.default_text_value,
      &initial_properties.default_number_value,
      &initial_properties.default_boolean_value
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the configuration.
    let configuration = Self::convert_from_row(&row);

    return Ok(configuration);

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

      "value_type" => {

        let value_type = match ConfigurationValueType::from_str(value) {

          Ok(value_type) => value_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

        };
        
        return Ok(Box::new(value_type));

      },

      _ => {

        return Ok(Box::new(value));

      }

    }

  }

  /// Returns a list of configurations based on a query.
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

  /// Updates this configuration and returns a new instance of the configuration.
  pub async fn update(&self, properties: &EditableConfigurationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("update configurations set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "name", Some(&properties.name));
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "description", properties.description.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "text_value", properties.text_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "number_value", properties.number_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "boolean_value", properties.boolean_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "default_text_value", properties.default_text_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "default_number_value", properties.default_number_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "default_boolean_value", properties.default_boolean_value.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" where id = ${} returning *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("commit;", &[]).await?;

    let configuration = Self::convert_from_row(&row);
    return Ok(configuration);

  }

}

impl DeletableResource for Configuration {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configurations/delete_configuration_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}