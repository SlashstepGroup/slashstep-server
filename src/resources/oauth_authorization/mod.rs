use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::{IndividualPrincipal}}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[];
pub const UUID_QUERY_KEYS: &[&str] = &[];
pub const RESOURCE_NAME: &str = "OAuthAuthorization";
pub const DATABASE_TABLE_NAME: &str = "oauth_authorizations";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.delegationPolicies.get";

/// A authorization that allows an app to trade a short-lived code for a longer-lived access token.
/// 
/// Since authorization codes are single-use, this resource is immutable.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthAuthorization {

  /// The OAuth authorization's ID.
  pub id: Uuid,
  
  /// The OAuth authorization's app ID. This is the same ID as the "client_id" in the OAuth2 specification.
  pub app_id: Uuid,

  /// The OAuth authorization's authorizing user ID.
  pub authorizing_user_id: Uuid,

  /// The OAuth authorization's code challenge, if applicable.
  pub code_challenge: Option<String>

}

pub struct InitialOAuthAuthorizationProperties {

  /// The OAuth authorization's app ID.
  pub app_id: Uuid,

  /// The OAuth authorization's authorizing user ID.
  pub authorizing_user_id: Uuid,

  /// The OAuth authorization's code challenge, if applicable.
  pub code_challenge: Option<String>,

  /// The OAuth authorization's scope.
  /// 
  /// Delegation policies are initially defined by this scope string.
  /// 
  /// The string should be a space-separated list of action IDs and permission levels.
  /// 
  /// For example: `00000000-0000-0000-0000-000000000001:Editor 00000000-0000-0000-0000-000000000002:Admin`
  pub scope: String

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer {

  /// The OAuth authorization's app ID.
  pub app_id: Uuid,

  /// The OAuth authorization's code challenge, if applicable.
  pub code_challenge: Option<String>,

  /// The OAuth authorization's scope.
  /// 
  /// Delegation policies are initially defined by this scope string.
  /// 
  /// The string should be a space-separated list of action IDs and permission levels.
  /// 
  /// For example: `00000000-0000-0000-0000-000000000001:Editor 00000000-0000-0000-0000-000000000002:Admin`
  pub scope: String
  
}

impl OAuthAuthorization {

  /// Initializes the oauth_authorizations table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/oauth_authorizations/initialize_oauth_authorizations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Converts a row from the database into an OAuth authorization.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return OAuthAuthorization {
      id: row.get("id"),
      app_id: row.get("app_id"),
      authorizing_user_id: row.get("authorizing_user_id"),
      code_challenge: row.get("code_challenge")
    }

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

  /// Creates a new oauth authorization.
  pub async fn create(initial_properties: &InitialOAuthAuthorizationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/oauth_authorizations/insert_oauth_authorization_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.authorizing_user_id,
      &initial_properties.code_challenge
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the oauth authorization.
    let oauth_authorization = Self::convert_from_row(&row);

    return Ok(oauth_authorization);

  }

  /// Returns a oauth authorization by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/oauth_authorizations/get_oauth_authorization_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An oauth authorization with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let oauth_authorization = Self::convert_from_row(&row);

    return Ok(oauth_authorization);

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

    return Ok(Box::new(value));

  }

}

impl DeletableResource for OAuthAuthorization {

  /// Deletes this oauth authorization.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/oauth_authorizations/delete_oauth_authorization_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}