#[cfg(test)]
mod tests;

use std::str::FromStr;

use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::{ActionPermissionLevel, IndividualPrincipal}}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "maximum_permission_level",
  "delegate_app_authorization_id",
  "principal_user_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "action_id",
  "delegate_app_authorization_id",
  "principal_user_id"
];
pub const RESOURCE_NAME: &str = "DelegationPolicy";
pub const DATABASE_TABLE_NAME: &str = "delegation_policies";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.delegationPolicies.get";

/// A piece of information that defines the maximum level of access that a delgate can use on behalf of a principal.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DelegationPolicy {

  /// The delegation policy's ID.
  pub id: Uuid,
  
  /// The delegation policy's action ID.
  pub action_id: Uuid,

  /// The delegation policy's maximum permission level.
  /// 
  /// The actual permission level is determined by the principal's permissions.
  /// 
  /// For example, if a principal has an access policy that grants them the "Editor" permission level and the delegation policy has a maximum permission level of "User", the actual permission level will be "User". Another example: if the maximum permission level is "Admin", the actual permission level will be "Editor" because the principal only has the "Editor" permission level.
  pub maximum_permission_level: ActionPermissionLevel,

  /// The delegation policy's delegate app authorization ID.
  pub delegate_app_authorization_id: Uuid,

  /// The delegation policy's principal user ID.
  pub principal_user_id: Uuid

}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct InitialDelegationPolicyProperties {

  /// The delegation policy's action ID.
  pub action_id: Uuid,

  /// The delegation policy's maximum permission level.
  pub maximum_permission_level: ActionPermissionLevel,

  /// The delegation policy's delegate app authorization ID.
  pub delegate_app_authorization_id: Uuid,

  /// The delegation policy's principal user ID.
  pub principal_user_id: Uuid

}

#[derive(Debug, Serialize, Deserialize)]
pub struct EditableDelegationPolicyProperties {

  /// The delegation policy's maximum permission level.
  pub maximum_permission_level: Option<ActionPermissionLevel>

}

impl DelegationPolicy {

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: Option<&T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    let parameter_value = parameter_value.and_then(|parameter_value| Some(parameter_value.clone()));
    if let Some(parameter_value) = parameter_value {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  /// Initializes the delegation_policies table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/delegation_policies/initialize_delegation_policies_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Converts a row from the database into a delegation policy.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return DelegationPolicy {
      id: row.get("id"),
      action_id: row.get("action_id"),
      maximum_permission_level: row.get("maximum_permission_level"),
      delegate_app_authorization_id: row.get("delegate_app_authorization_id"),
      principal_user_id: row.get("principal_user_id")
    };

  }

  /// Counts the number of delegation policies based on a query.
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

  /// Creates a new delegation policy.
  pub async fn create(initial_properties: &InitialDelegationPolicyProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/delegation_policies/insert_delegation_policy_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.action_id,
      &initial_properties.maximum_permission_level,
      &initial_properties.delegate_app_authorization_id,
      &initial_properties.principal_user_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the delegation policy.
    let delegation_policy = Self::convert_from_row(&row);

    return Ok(delegation_policy);

  }

  /// Returns a delegation policy by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/delegation_policies/get_delegation_policy_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An delegation policy with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let delegation_policy = Self::convert_from_row(&row);

    return Ok(delegation_policy);

  }

  /// Returns a list of delegation policies based on a query.
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

  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    match key {

      "maximum_permission_level" => {

        let permission_level = match ActionPermissionLevel::from_str(value) {

          Ok(permission_level) => permission_level,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse ActionPermissionLevel from \"{}\" for key \"{}\".", value, key)))

        };

        return Ok(Box::new(permission_level));

      },

      _ => {}

    }

    return Ok(Box::new(value));

  }

  /// Updates this delegation policy and returns a new instance of the delegation policy.
  pub async fn update(&self, properties: &EditableDelegationPolicyProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE delegation_policies SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "maximum_permission_level", properties.maximum_permission_level.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let delegation_policy = Self::convert_from_row(&row);
    return Ok(delegation_policy);

  }

}

impl DeletableResource for DelegationPolicy {

  /// Deletes this delegation policy.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/delegation_policies/delete_delegation_policy_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}