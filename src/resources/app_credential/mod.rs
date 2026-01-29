use std::net::IpAddr;
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_APP_CREDENTIAL_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_APP_CREDENTIAL_LIST_LIMIT: i64 = 1000;
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
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.appCredentials.get";

/// A credential that can be used to generate JSON web tokens (JWT) for apps so that they can authenticate with Slashstep Server.
/// To protect the app, Slashstep Server only stores the app credential's metadata and public key. App admins are responsible for managing the private key. 
#[derive(Debug, Serialize, Deserialize)]
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
  pub async fn initialize_app_credentials_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), ResourceError> {

    let query = include_str!("../../queries/app-credentials/initialize-app-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
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
  pub async fn count(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, ResourceError> {

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
    let rows = postgres_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  pub async fn create(initial_properties: &InitialAppCredentialProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app-credentials/insert-app-credential-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.description,
      &initial_properties.expiration_date,
      &initial_properties.creation_ip_address,
      &initial_properties.public_key
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app credential.
    let app_credential = AppCredential::convert_from_row(&row);

    return Ok(app_credential);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app-credentials/get-app-credential-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

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
  pub async fn list(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_APP_CREDENTIAL_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_APP_CREDENTIAL_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let rows = postgres_client.query(&query, &parameters).await?;
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

}