use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use crate::{resources::access_policy::IndividualPrincipal, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_APP_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_APP_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "display_name",
  "description",
  "client_type",
  "parent_resource_type",
  "parent_workspace_id",
  "parent_user_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_workspace_id",
  "parent_user_id"
];
pub const RESOURCE_NAME: &str = "App";
pub const DATABASE_TABLE_NAME: &str = "apps";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.apps.get";

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Serialize, Deserialize)]
#[postgres(name = "app_client_type")]
pub enum AppClientType {
  Public,
  Confidential
}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Serialize, Deserialize)]
#[postgres(name = "app_parent_resource_type")]
pub enum AppParentResourceType {
  Instance,
  User,
  Workspace
}

#[derive(Debug, Error)]
pub enum AppError {
  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error("An app with the name \"{0}\" already exists.")]
  ConflictError(String),

  #[error("An app with the ID \"{0}\" does not exist.")]
  NotFoundError(String),

  #[error(transparent)]
  SlashstepQLError(#[from] SlashstepQLError)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
  pub id: Uuid,
  pub name: String,
  pub display_name: String,
  pub description: Option<String>,
  pub client_type: AppClientType,
  pub client_secret_hash: String,
  pub parent_resource_type: AppParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_user_id: Option<Uuid>
}

pub struct InitialAppProperties {
  pub name: String,
  pub display_name: String,
  pub description: Option<String>,
  pub client_type: AppClientType,
  pub client_secret_hash: String,
  pub parent_resource_type: AppParentResourceType,
  pub parent_workspace_id: Option<Uuid>,
  pub parent_user_id: Option<Uuid>
}

impl App {

  /// Initializes the apps table.
  pub async fn initialize_apps_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppError> {

    let query = include_str!("../../queries/apps/initialize-apps-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub fn convert_from_row(row: &postgres::Row) -> Self {

    return App {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      client_type: row.get("client_type"),
      client_secret_hash: row.get("client_secret_hash"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_user_id: row.get("parent_user_id")
    };

  }

  /// Counts the number of apps based on a query.
  pub async fn count(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, AppError> {

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

  /// Creates a new app.
  pub async fn create(initial_properties: &InitialAppProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AppError> {

    let query = include_str!("../../queries/apps/insert-app-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.client_type,
      &initial_properties.client_secret_hash,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_workspace_id,
      &initial_properties.parent_user_id
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => AppError::ConflictError(initial_properties.name.to_string()),
        
        _ => AppError::PostgresError(error)

      },

      None => AppError::PostgresError(error)

    })?;

    // Return the action.
    let app = Self::convert_from_row(&row);

    return Ok(app);

  }

  /// Deletes an app.
  pub async fn delete(&self, postgres_client: &mut deadpool_postgres::Client) -> Result<(), AppError> {

    let query = include_str!("../../queries/apps/delete-app-row-by-id.sql");
    postgres_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Gets an app by its ID.
  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, AppError> {

    let query = include_str!("../../queries/apps/get-app-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(AppError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(AppError::PostgresError(error))

    };

    let app = Self::convert_from_row(&row);

    return Ok(app);

  }

  /// Returns a list of apps based on a query.
  pub async fn list(query: &str, postgres_client: &mut deadpool_postgres::Client, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, AppError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_APP_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_APP_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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