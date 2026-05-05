/**
 * 
 * This module defines the implementation and types of a role.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

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
  "parent_group_id",
  "protected_role_type"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_workspace_id",
  "parent_project_id",
  "parent_group_id"
];
pub const RESOURCE_NAME: &str = "Role";
pub const DATABASE_TABLE_NAME: &str = "roles";
pub const GET_RESOURCE_ACTION_NAME: &str = "roles.get";

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone, Copy, Serialize, Deserialize, Default)]
#[postgres(name = "role_parent_resource_type")]
pub enum RoleParentResourceType {
  #[default]
  Server,
  Workspace,
  Project,
  Group
}

#[derive(Debug, Clone, Serialize, ToSql, FromSql, Deserialize, PartialEq, Eq)]
#[postgres(name = "protected_role_type")]
pub enum ProtectedRoleType {
  
  /// A role intended for unauthenticated users.
  /// 
  /// This role is automatically created when Slashstep Server is initialized. 
  /// 
  /// This role should be protected from deletion because deleting this role may cause the server to break.
  AnonymousUsers,

  /// A role intended for group admins.
  /// 
  /// This role is automatically created when a group is created.
  /// 
  /// This role should be protected from deletion to ease the transition in case there is an update to
  /// the default permissions.
  GroupAdmins,

  /// A role intended for group members.
  /// 
  /// This role is automatically created when a group is created.
  /// 
  /// This role should be protected from deletion to ease the transition in case there is an update to
  /// the default permissions.
  GroupMembers,


  /// A role intended for server admins.
  /// 
  /// This role is automatically created when Slashstep Server is initialized.
  /// 
  /// This role should be protected from deletion to ease the transition in case there is an update to the default permissions.
  ServerAdmins

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

  /// The role's protected role type, if applicable.
  /// 
  /// If the role has a protected role type, then the role cannot be deleted directly
  /// using Slashstep Server's REST API. 
  ///
  /// If one *really* needs to delete a protected role, 
  /// one should delete the parent resource. One technically can delete it through other means 
  /// (i.e. querying the database, editing Slashstep Server source code, etc.); but,
  /// deleting the role may cause a worse user experience, require admin intervention, 
  /// or even break the server.
  pub protected_role_type: Option<ProtectedRoleType>
  
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditableRoleProperties {

  /// The role's name.
  pub name: Option<String>,

  /// The role's display name.
  pub display_name: Option<String>,

  /// The role's description.
  pub description: Option<Option<String>>
  
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct EditableRolePropertiesRequestBody {

  /// The role's name.
  pub name: Option<String>,

  /// The role's display name.
  pub display_name: Option<String>,

  /// The role's description.
  #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_with::rust::double_option")]
  pub description: Option<Option<String>>

}

impl From<EditableRolePropertiesRequestBody> for EditableRoleProperties {

  fn from(request_body: EditableRolePropertiesRequestBody) -> Self {

    return EditableRoleProperties {
      name: request_body.name,
      display_name: request_body.display_name,
      description: request_body.description
    };

  }

}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitialRolePropertiesWithPredefinedParent {

  /// The role's name.
  pub name: String,

  /// The role's display name.
  pub display_name: String,

  /// The role's description.
  pub description: Option<String>

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

  /// The role's protected role type, if applicable.
  /// 
  /// If the role has a protected role type, then the role cannot be deleted directly
  /// using Slashstep Server's REST API. 
  ///
  /// If one *really* needs to delete a protected role, 
  /// one should delete the parent resource. One technically can delete it through other means 
  /// (i.e. querying the database, editing Slashstep Server source code, etc.); but,
  /// deleting the role may cause a worse user experience, require admin intervention, 
  /// or even break the server.
  pub protected_role_type: Option<ProtectedRoleType>
}

impl Role {

  /// Counts the number of roles based on a query.
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
      protected_role_type: row.get("protected_role_type")
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
      &initial_properties.protected_role_type
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => {

        match db_error.code() {

          &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError("A role with the same name and parent resource type already exists.".to_string()),
          
          _ => ResourceError::PostgresError(error)

        }

      },

      None => ResourceError::PostgresError(error)
    
    })?;

    // Return the role.
    let role = Self::convert_from_row(&row);

    return Ok(role);

  }

  /// Deletes this field.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/roles/delete_role_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Returns a list of roles based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
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

  /// Updates this role and returns a new instance of the role.
  pub async fn update(&self, properties: &EditableRoleProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE roles SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "name", properties.name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", properties.display_name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "description", properties.description.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let status = Self::convert_from_row(&row);
    return Ok(status);

  }

}
