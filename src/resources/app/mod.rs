use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

#[cfg(test)]
mod tests;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditableAppProperties {
  pub name: Option<String>,
  pub display_name: Option<String>,
  pub description: Option<String>,
  pub client_type: Option<AppClientType>
}

impl App {

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: &Option<T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    if let Some(parameter_value) = parameter_value.clone() {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }

  /// Initializes the apps table.
  pub async fn initialize_apps_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/apps/initialize_apps_table.sql");
    database_client.execute(query, &[]).await?;
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

  /// Creates a new app.
  pub async fn create(initial_properties: &InitialAppProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/apps/insert_app_row.sql");
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
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError(initial_properties.name.to_string()),
        
        _ => ResourceError::PostgresError(error)

      },

      None => ResourceError::PostgresError(error)

    })?;

    // Return the action.
    let app = Self::convert_from_row(&row);

    return Ok(app);

  }

  /// Gets an app by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/apps/get_app_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("An app with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app = Self::convert_from_row(&row);

    return Ok(app);

  }

  /// Returns a list of apps based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

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

  /// Updates this app and returns a new instance of the app.
  pub async fn update(&self, properties: &EditableAppProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE apps SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

    let database_client = database_pool.get().await?;
    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "name", &properties.name);
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "display_name", &properties.display_name);
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "description", &properties.description);
    let (mut parameter_boxes, mut query) = Self::add_parameter(parameter_boxes, query, "client_type", &properties.client_type);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let app = Self::convert_from_row(&row);
    return Ok(app);

  }

}

impl DeletableResource for App {

  /// Deletes this app.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/apps/delete_app_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}