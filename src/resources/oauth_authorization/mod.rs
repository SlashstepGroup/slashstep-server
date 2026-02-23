use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Header;
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
  pub code_challenge: Option<String>,

  /// The OAuth authorization's code challenge method, if applicable.
  pub code_challenge_method: Option<String>,

  /// The OAuth authorization's redirect URI, if applicable.
  pub redirect_uri: Option<String>,

  /// The OAuth authorization's scope.
  pub scope: String,

  /// The OAuth authorization's usage date, if applicable.
  pub usage_date: Option<DateTime<Utc>>,

  /// The OAuth authorization's state, if applicable.
  pub state: Option<String>

}

pub struct InitialOAuthAuthorizationProperties {

  /// The OAuth authorization's app ID.
  pub app_id: Uuid,

  /// The OAuth authorization's authorizing user ID.
  pub authorizing_user_id: Uuid,

  /// The OAuth authorization's code challenge, if applicable.
  pub code_challenge: Option<String>,

  /// The OAuth authorization's code challenge method, if applicable.
  pub code_challenge_method: Option<String>,

  /// The OAuth authorization's scope.
  /// 
  /// Delegation policies are initially defined by this scope string.
  /// 
  /// The string should be a space-separated list of action IDs and permission levels.
  /// 
  /// For example: `00000000-0000-0000-0000-000000000001:Editor 00000000-0000-0000-0000-000000000002:Admin`
  pub scope: String,

  /// The OAuth authorization's redirect URI, if applicable.
  pub redirect_uri: Option<String>,

  /// The OAuth authorization's usage date, if applicable.
  pub usage_date: Option<DateTime<Utc>>,

  /// The OAuth authorization's state, if applicable.
  pub state: Option<String>

}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InitialOAuthAuthorizationPropertiesForPredefinedAuthorizer {

  /// The OAuth authorization's app ID.
  pub app_id: Uuid,

  /// The OAuth authorization's code challenge, if applicable.
  pub code_challenge: Option<String>,

  /// The OAuth authorization's code challenge method, if applicable.
  pub code_challenge_method: Option<String>,

  /// The OAuth authorization's scope.
  /// 
  /// Delegation policies are initially defined by this scope string.
  /// 
  /// The string should be a space-separated list of action IDs and permission levels.
  /// 
  /// For example: `00000000-0000-0000-0000-000000000001:Editor 00000000-0000-0000-0000-000000000002:Admin`
  pub scope: String,

  /// The OAuth authorization's redirect URI, if applicable.
  pub redirect_uri: Option<String>,

  /// The OAuth authorization's state, if applicable.
  pub state: Option<String>
  
}

pub struct EditableOAuthAuthorizationProperties {

  pub usage_date: Option<DateTime<Utc>>

}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthAuthorizationClaims {
  pub jti: String,
  pub exp: usize
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
      code_challenge: row.get("code_challenge"),
      code_challenge_method: row.get("code_challenge_method"),
      redirect_uri: row.get("redirect_uri"),
      scope: row.get("scope"),
      usage_date: row.get("usage_date"),
      state: row.get("state")
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
      &initial_properties.code_challenge,
      &initial_properties.code_challenge_method,
      &initial_properties.redirect_uri,
      &initial_properties.scope,
      &initial_properties.usage_date,
      &initial_properties.state
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the oauth authorization.
    let oauth_authorization = Self::convert_from_row(&row);

    return Ok(oauth_authorization);

  }

  pub fn generate_authorization_code(&self, private_key: &str) -> Result<String, ResourceError> {

    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    let expiration_date = Utc::now() + Duration::seconds(60); // TODO: Make this configurable.
    let claims = OAuthAuthorizationClaims {
      jti: self.id.to_string(),
      exp: (expiration_date.timestamp_millis() as usize)
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
    return Ok(token);

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

  pub async fn update(&self, properties: &EditableOAuthAuthorizationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE oauth_authorizations SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (mut parameter_boxes, mut query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "usage_date", Some(&properties.usage_date));

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let oauth_authorization = OAuthAuthorization::convert_from_row(&row);
    return Ok(oauth_authorization);

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