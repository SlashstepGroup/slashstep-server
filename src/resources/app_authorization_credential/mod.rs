#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use jsonwebtoken::Header;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "app_authorization_id",
  "access_token_expiration_date",
  "refresh_token_expiration_date",
  "refreshed_app_authorization_credential_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "app_authorization_id",
  "refreshed_app_authorization_credential_id"
];
pub const RESOURCE_NAME: &str = "AppAuthorizationCredential";
pub const DATABASE_TABLE_NAME: &str = "app_authorization_credentials";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.appAuthorizationCredentials.get";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppAuthorizationCredential {

  /// The ID of the app authorization credential.
  pub id: Uuid,

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid,

  /// The expiration date of the access token.
  pub access_token_expiration_date: DateTime<Utc>,

  /// The expiration date of the refresh token.
  pub refresh_token_expiration_date: DateTime<Utc>,

  /// The ID of the refreshed app authorization credential, if applicable.
  pub refreshed_app_authorization_credential_id: Option<Uuid>

}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct InitialAppAuthorizationCredentialProperties {

  /// The ID of the app authorization.
  pub app_authorization_id: Uuid,

  /// The expiration date of the access token.
  pub access_token_expiration_date: DateTime<Utc>,

  /// The expiration date of the refresh token.
  pub refresh_token_expiration_date: DateTime<Utc>,

  /// The ID of the refreshed app authorization credential, if applicable.
  pub refreshed_app_authorization_credential_id: Option<Uuid>

}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppAuthorizationCredentialClaims {
  pub jti: String,
  pub exp: usize,
  pub r#type: String
}

impl AppAuthorizationCredential {

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppAuthorizationCredential {
      id: row.get("id"),
      app_authorization_id: row.get("app_authorization_id"),
      access_token_expiration_date: row.get("access_token_expiration_date"),
      refresh_token_expiration_date: row.get("refresh_token_expiration_date"),
      refreshed_app_authorization_credential_id: row.get("refreshed_app_authorization_credential_id")
    };

  }

  /// Counts the number of app authorizations based on a query.
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

  pub async fn create(initial_properties: &InitialAppAuthorizationCredentialProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app_authorization_credentials/insert_app_authorization_credential_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_authorization_id,
      &DateTime::from_timestamp_millis(initial_properties.access_token_expiration_date.timestamp_millis()),
      &DateTime::from_timestamp_millis(initial_properties.refresh_token_expiration_date.timestamp_millis()),
      &initial_properties.refreshed_app_authorization_credential_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization credential.
    let app_authorization_credential = Self::convert_from_row(&row);

    return Ok(app_authorization_credential);

  }

  pub fn generate_access_token(&self, private_key: &str) -> Result<String, ResourceError> {

    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    let claims = AppAuthorizationCredentialClaims {
      jti: self.id.to_string(),
      exp: self.access_token_expiration_date.timestamp() as usize,
      r#type: "Access".to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

    return Ok(token);

  }

  pub fn generate_refresh_token(&self, private_key: &str) -> Result<String, ResourceError> {

    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    let claims = AppAuthorizationCredentialClaims {
      jti: self.id.to_string(),
      exp: self.refresh_token_expiration_date.timestamp() as usize,
      r#type: "Refresh".to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

    return Ok(token);

  }

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/get_app_authorization_credential_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An app authorization credential with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization_credential = Self::convert_from_row(&row);

    return Ok(app_authorization_credential);

  }

  /// Initializes the app_authorization_credentials table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/initialize_app_authorization_credentials_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Returns a list of app authorizations based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_APP_AUTHORIZATION_CREDENTIAL_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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

}

impl DeletableResource for AppAuthorizationCredential {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorization_credentials/delete_app_authorization_credential_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}