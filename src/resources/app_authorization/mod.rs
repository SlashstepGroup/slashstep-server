#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_APP_AUTHORIZATION_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_APP_AUTHORIZATION_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "app_id",
  "authorizing_resource_type",
  "authorizing_project_id",
  "authorizing_workspace_id",
  "authorizing_user_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "app_id",
  "authorizing_project_id",
  "authorizing_workspace_id",
  "authorizing_user_id"
];
pub const RESOURCE_NAME: &str = "AppAuthorization";
pub const DATABASE_TABLE_NAME: &str = "app_authorizations";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.appAuthorizations.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, Default, PartialEq, Eq)]
#[postgres(name = "app_authorization_authorizing_resource_type")]
pub enum AppAuthorizationAuthorizingResourceType {
  #[default]
  Instance,
  Workspace,
  Project,
  User
}

#[derive(Debug, Clone, Default)]
pub struct InitialAppAuthorizationProperties {

  /// The ID of the app.
  pub app_id: Uuid,

  /// The parent resource type of the app authorization.
  pub authorizing_resource_type: AppAuthorizationAuthorizingResourceType,

  /// The ID of the parent project of the app authorization, if applicable.
  pub authorizing_project_id: Option<Uuid>,

  /// The ID of the parent workspace of the app authorization, if applicable.
  pub authorizing_workspace_id: Option<Uuid>,

  /// The ID of the parent user of the app authorization, if applicable.
  pub authorizing_user_id: Option<Uuid>

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthorization {

  /// The ID of the app authorization.
  pub id: Uuid,

  /// The ID of the app.
  pub app_id: Uuid,

  /// The parent resource type of the app authorization.
  pub authorizing_resource_type: AppAuthorizationAuthorizingResourceType,

  /// The ID of the parent project of the app authorization, if applicable.
  pub authorizing_project_id: Option<Uuid>,

  /// The ID of the parent workspace of the app authorization, if applicable.
  pub authorizing_workspace_id: Option<Uuid>,

  /// The ID of the parent user of the app authorization, if applicable.
  pub authorizing_user_id: Option<Uuid>

}

impl AppAuthorization {

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

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/get_app_authorization_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An app authorization with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization = Self::convert_from_row(&row);

    return Ok(app_authorization);

  }

  fn convert_from_row(row: &postgres::Row) -> Self {

    return AppAuthorization {
      id: row.get("id"),
      app_id: row.get("app_id"),
      authorizing_resource_type: row.get("authorizing_resource_type"),
      authorizing_project_id: row.get("authorizing_project_id"),
      authorizing_workspace_id: row.get("authorizing_workspace_id"),
      authorizing_user_id: row.get("authorizing_user_id")
    };

  }

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/initialize_app_authorizations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub async fn create(initial_properties: &InitialAppAuthorizationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/app_authorizations/insert_app_authorization_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.app_id,
      &initial_properties.authorizing_resource_type,
      &initial_properties.authorizing_project_id,
      &initial_properties.authorizing_workspace_id,
      &initial_properties.authorizing_user_id
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

  /// Returns a list of app authorizations based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_APP_AUTHORIZATION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_APP_AUTHORIZATION_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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

}

impl DeletableResource for AppAuthorization {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/app_authorizations/delete_app_authorization_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}