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
  "value_type",
  "text_value",
  "integer_value",
  "decimal_value",
  "boolean_value"
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
  Integer,
  Decimal,
  Boolean
}

impl FromStr for ConfigurationValueType {

  type Err = ResourceError;

  fn from_str(input: &str) -> Result<ConfigurationValueType, Self::Err> {

    match input {

      "Text" => Ok(ConfigurationValueType::Text),
      "Integer" => Ok(ConfigurationValueType::Integer),
      "Decimal" => Ok(ConfigurationValueType::Decimal),
      "Boolean" => Ok(ConfigurationValueType::Boolean),
      _ => Err(ResourceError::UnexpectedEnumVariantError(input.to_string()))

    }

  }

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InitialConfigurationProperties {

  /// The configuration's name.
  pub name: String,

  /// The configuration's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's integer value, if applicable.
  pub integer_value: Option<i32>,

  /// The configuration's decimal value, if applicable.
  pub decimal_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EditableConfigurationProperties {

  /// The configuration's name.
  pub name: Option<String>,

  /// The configuration's value type.
  pub value_type: Option<ConfigurationValueType>,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's integer value, if applicable.
  pub integer_value: Option<i32>,

  /// The configuration's decimal value, if applicable.
  pub decimal_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Configuration {

  /// The configuration's ID.
  pub id: Uuid,
  
  /// The configuration's name.
  pub name: String,

  /// The configuration's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration's integer value, if applicable.
  pub integer_value: Option<i32>,

  /// The configuration's decimal value, if applicable.
  pub decimal_value: Option<Decimal>,

  /// The configuration's boolean value, if applicable.
  pub boolean_value: Option<bool>

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

  /// Converts a row into a configuration.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Configuration {
      id: row.get("id"),
      name: row.get("name"),
      value_type: row.get("value_type"),
      text_value: row.get("text_value"),
      integer_value: row.get("integer_value"),
      decimal_value: row.get("decimal_value"),
      boolean_value: row.get("boolean_value")
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
      &initial_properties.value_type,
      &initial_properties.text_value,
      &initial_properties.integer_value,
      &initial_properties.decimal_value,
      &initial_properties.boolean_value
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
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "value_type", Some(&properties.value_type));
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "text_value", Some(&properties.text_value));
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "integer_value", Some(&properties.integer_value));
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "decimal_value", Some(&properties.decimal_value));
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "boolean_value", Some(&properties.boolean_value));
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