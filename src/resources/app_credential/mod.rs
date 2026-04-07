/**
 * 
 * This module defines the implementation and types of an app credential.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "app_id",
  "description",
  "expiration_date",
  "creation_ip_address",
  "public_key"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "app_id"
];
pub const RESOURCE_NAME: &str = "AppCredential";
pub const DATABASE_TABLE_NAME: &str = "app_credentials";
pub const GET_RESOURCE_ACTION_NAME: &str = "appCredentials.get";

/// A credential that can be used to generate JSON web tokens (JWT) for apps so that they can authenticate with Slashstep Server.
/// To protect the app, Slashstep Server only stores the app credential's metadata and public key. App admins are responsible for managing the private key. 
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppCredential {

  /// The app credential's ID.
  pub id: Uuid,

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>,

  /// The app credential's creation IP address.
  pub creation_ip_address: IpAddr,

  /// The app credential's public key.
  pub public_key: String

}

pub struct InitialAppCredentialProperties {

  /// The app credential's app ID.
  pub app_id: Uuid,

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>,

  /// The app credential's creation IP address.
  pub creation_ip_address: IpAddr,

  /// The app credential's public key.
  pub public_key: String

}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialAppCredentialPropertiesForPredefinedScope {

  /// The app credential's description, if applicable.
  pub description: Option<String>,

  /// The app credential's expiration date, if applicable.
  pub expiration_date: Option<DateTime<Utc>>

}

impl AppCredential {

  /// Initializes the app_credentials table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_credentials/initialize_app_credentials_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppCredential {
      id: row.get("id"),
      app_id: row.get("app_id"),
      description: row.get("description"),
      expiration_date: row.get("expiration_date"),
      creation_ip_address: row.get("creation_ip_address"),
      public_key: row.get("public_key")
    };

  }

  /// Counts the number of app credentials based on a query.
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

  pub async fn create(initial_properties: &InitialAppCredentialProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app_credentials/insert_app_credential_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.description,
      &initial_properties.expiration_date.and_then(|expiration_date| DateTime::from_timestamp_millis(expiration_date.timestamp_millis())),
      &initial_properties.creation_ip_address,
      &initial_properties.public_key
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app credential.
    let app_credential = AppCredential::convert_from_row(&row);

    return Ok(app_credential);

  }

  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_credentials/delete_app_credential_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_credentials/get_app_credential_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An app credential with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

  /// Returns a list of app credentials based on a query.
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

}
