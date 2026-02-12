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
  "description",
  "parent_resource_type",
  "parent_workspace_id",
  "parent_project_id",
  "parent_group_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_workspace_id",
  "parent_project_id",
  "parent_group_id"
];
pub const RESOURCE_NAME: &str = "Role";
pub const DATABASE_TABLE_NAME: &str = "roles";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.roles.get";

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Serialize, Deserialize, Default)]
#[postgres(name = "role_parent_resource_type")]
pub enum RoleParentResourceType {
  #[default]
  Server,
  Workspace,
  Project,
  Group
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitialRoleProperties {

  /// The role's name.
  pub name: String,

  /// The role's display name.
  pub display_name: String,

  /// The role's description.
  pub description: Option<String>,

  /// The role's parent resource type.
  pub parent_resource_type: RoleParentResourceType,

  /// The role's parent workspace ID, if applicable.
  pub parent_workspace_id: Option<Uuid>,

  /// The role's parent project ID, if applicable.
  pub parent_project_id: Option<Uuid>,

  /// The role's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,

  /// Whether the role is predefined.
  pub is_predefined: bool
  
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {

  /// The role's ID.
  pub id: Uuid,

  /// The role's name.
  pub name: String,

  /// The role's display name.
  pub display_name: String,

  /// The role's description.
  pub description: Option<String>,

  /// The role's parent resource type.
  pub parent_resource_type: RoleParentResourceType,

  /// The role's parent workspace ID, if applicable.
  pub parent_workspace_id: Option<Uuid>,

  /// The role's parent project ID, if applicable.
  pub parent_project_id: Option<Uuid>,

  /// The role's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,
  
  /// Whether the role is predefined.
  pub is_predefined: bool,
}

impl Role {

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
    let query = include_str!("../../queries/roles/get_role_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A role with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Gets a role by its name.
  pub async fn get_by_name(name: &str, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/get_role_row_by_name.sql");
    let row = match database_client.query_opt(query, &[&name]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(name.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let role = Self::convert_from_row(&row);

    return Ok(role);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Role {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_project_id: row.get("parent_project_id"),
      parent_group_id: row.get("parent_group_id"),
      is_predefined: row.get("is_predefined")
    };

  }

  /// Initializes the roles table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/initialize_roles_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialRoleProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/roles/insert_role_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_group_id,
      &initial_properties.parent_workspace_id,
      &initial_properties.parent_project_id,
      &initial_properties.is_predefined
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the role.
    let role = Self::convert_from_row(&row);

    return Ok(role);

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
    let actions = rows.iter().map(Self::convert_from_row).collect();
    return Ok(actions);

  }

}

impl DeletableResource for Role {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/delete_role_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}