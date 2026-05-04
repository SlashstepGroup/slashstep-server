/**
 * 
 * This module defines the implementation and types of a password reset token.
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
use jsonwebtoken::Header;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_PASSWORD_RESET_AUTHORIZATION_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "user_id",
  "expiration_date"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "user_id"
];
pub const RESOURCE_NAME: &str = "PasswordResetAuthorization";
pub const DATABASE_TABLE_NAME: &str = "password_reset_authorizations";
pub const GET_RESOURCE_ACTION_NAME: &str = "passwordResetAuthorizations.get";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordResetAuthorization {

  /// The ID of the password reset token.
  pub id: Uuid,

  /// The ID of the user.
  pub user_id: Uuid,

  /// The expiration date of the access token.
  pub expiration_date: DateTime<Utc>

}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct InitialPasswordResetAuthorizationProperties {

  /// The ID of the user.
  pub user_id: Uuid,

  /// The expiration date of the access token.
  pub expiration_date: DateTime<Utc>

}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetAuthorizationClaims {
  pub jti: String,
  pub sub: String,
  pub exp: usize
}

impl PasswordResetAuthorization {

  fn convert_from_row(row: &postgres::Row) -> Self {

    return PasswordResetAuthorization {
      id: row.get("id"),
      user_id: row.get("user_id"),
      expiration_date: row.get("expiration_date")
    };

  }

  /// Counts the number of password reset tokens based on a query.
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

  /// Creates a password reset token with the specified properties and returns it.
  pub async fn create(initial_properties: &InitialPasswordResetAuthorizationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/password_reset_authorizations/insert_password_reset_authorization_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.user_id,
      &DateTime::from_timestamp_millis(initial_properties.expiration_date.timestamp_millis())
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the password reset token.
    let password_reset_authorization = Self::convert_from_row(&row);

    return Ok(password_reset_authorization);

  }

  /// Deletes the password reset token. 
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/password_reset_authorizations/delete_password_reset_authorization_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Generates a JSON web token for the password reset token.
  pub fn generate_token(&self, private_key: &str) -> Result<String, ResourceError> {

    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    let claims = PasswordResetAuthorizationClaims {
      jti: self.id.to_string(),
      sub: self.user_id.to_string(),
      exp: self.expiration_date.timestamp() as usize
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

    return Ok(token);

  }

  /// Gets a password reset token by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/password_reset_authorizations/get_password_reset_authorization_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A password reset token with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let password_reset_authorization = Self::convert_from_row(&row);

    return Ok(password_reset_authorization);

  }

  /// Initializes the password_reset_authorizations table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/password_reset_authorizations/initialize_password_reset_authorizations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Returns a list of password reset tokens based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      default_limit: Some(DEFAULT_PASSWORD_RESET_AUTHORIZATION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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

}
