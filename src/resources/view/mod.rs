#[cfg(test)]
mod tests;

use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "name",
  "display_name",
  "default_query",
  "type",
  "parent_resource_type",
  "parent_workspace_id",
  "parent_project_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_workspace_id",
  "parent_project_id"
];
pub const RESOURCE_NAME: &str = "View";
pub const DATABASE_TABLE_NAME: &str = "views";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.views.get";

#[derive(Debug, Clone, Serialize, Deserialize, FromSql, ToSql, Default, PartialEq, Eq)]
#[postgres(name = "view_type")]
pub enum ViewType {
  Table,
  Kanban,
  #[default]
  List,
  Timeline
}

#[derive(Debug, Clone, Serialize, Deserialize, FromSql, ToSql, Default, PartialEq, Eq)]
#[postgres(name = "view_parent_resource_type")]
pub enum ViewParentResourceType {
  #[default]
  Workspace,
  Project
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {

  /// The view's ID.
  pub id: Uuid,

  /// The name of the view.
  pub name: String,

  /// The display name of the view.
  pub display_name: String,
  
  /// The default query of the view, if applicable.
  pub default_query: Option<String>,

  /// The type of the view.
  pub r#type: ViewType,

  /// The parent resource type of the view.
  pub parent_resource_type: ViewParentResourceType,

  /// The ID of the parent workspace, if applicable.
  pub parent_workspace_id: Option<Uuid>,

  /// The ID of the parent project, if applicable.
  pub parent_project_id: Option<Uuid>,

}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct InitialViewProperties {

  /// The name of the view.
  pub name: String,

  /// The display name of the view.
  pub display_name: String,

  /// The default query of the view, if applicable.
  pub default_query: Option<String>,

  /// The type of the view.
  pub r#type: ViewType,

  /// The parent resource type of the view.
  pub parent_resource_type: ViewParentResourceType,

  /// The ID of the parent workspace, if applicable.
  pub parent_workspace_id: Option<Uuid>,

  /// The ID of the parent project, if applicable.
  pub parent_project_id: Option<Uuid>,

}

impl View {

  /// Counts the number of roles based on a query.
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

  /// Gets a field by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/views/get_view_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A view with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let view = Self::convert_from_row(&row);

    return Ok(view);

  }

  /// Converts a row into a view.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Self {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      default_query: row.get("default_query"),
      r#type: row.get("type"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_project_id: row.get("parent_project_id")
    };

  }

  /// Initializes the views table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/views/initialize_views_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new view.
  pub async fn create(initial_properties: &InitialViewProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/views/insert_view_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.default_query,
      &initial_properties.r#type,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_workspace_id,
      &initial_properties.parent_project_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    let view = Self::convert_from_row(&row);

    return Ok(view);

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

  /// Returns a list of roles based on a query.
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
    let views = rows.iter().map(Self::convert_from_row).collect();
    return Ok(views);

  }

}

impl DeletableResource for View {

  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/views/delete_view_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;

    return Ok(());

  }

}