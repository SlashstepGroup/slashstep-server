/*
 *
 * This module defines the implementation and types of a group.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use core::fmt;

use crate::{
    resources::{ResourceError, access_policy::AccessPolicyPrincipalType},
    utilities::slashstepql::{
        self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult,
        SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter,
        SlashstepQLSanitizeFunctionOptions,
    },
};
use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
    "id",
    "name",
    "display_name",
    "description",
    "parent_resource_type",
    "parent_group_id",
    "predefined_group_type",
];
pub const UUID_QUERY_KEYS: &[&str] = &["id", "parent_group_id"];
pub const RESOURCE_NAME: &str = "Group";
pub const DATABASE_TABLE_NAME: &str = "groups";
pub const GET_RESOURCE_ACTION_NAME: &str = "groups.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "group_parent_resource_type")]
pub enum GroupParentResourceType {
    #[default]
    Server,
    Group,
}

#[derive(Debug, Clone, Serialize, ToSql, FromSql, Deserialize, PartialEq, Eq, Hash)]
#[postgres(name = "predefined_group_type")]
pub enum PredefinedGroupType {
    /// A group intended for unauthenticated users.
    ///
    /// This group is automatically created when Slashstep Server is initialized.
    ///
    /// This group should be protected from deletion because deleting this group may cause the server to break.
    AnonymousUsers,

    /// A group intended for registered users.
    ///
    /// This group is automatically created when Slashstep Server is initialized.
    ///
    /// This group should be protected from deletion because deleting this group may cause the server to break.
    RegisteredUsers,
}

impl fmt::Display for PredefinedGroupType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PredefinedGroupType::AnonymousUsers => write!(f, "AnonymousUsers"),
            PredefinedGroupType::RegisteredUsers => write!(f, "RegisteredUsers"),
        }
    }
}

#[derive(Debug, Clone, ToSql, FromSql, Default, Serialize, Deserialize)]
pub struct InitialGroupProperties {
    /// The group's name.
    pub name: String,

    /// The group's display name.
    pub display_name: String,

    /// The group's description, if applicable.
    pub description: Option<String>,

    /// The group's parent resource type.
    pub parent_resource_type: GroupParentResourceType,

    /// The group's parent group ID, if applicable.
    pub parent_group_id: Option<Uuid>,

    /// The group's protected group type, if applicable.
    pub predefined_group_type: Option<PredefinedGroupType>,
}

#[derive(Debug, Clone, ToSql, FromSql, Default, Serialize, Deserialize)]
pub struct EditableGroupProperties {
    /// The group's name.
    pub name: Option<String>,

    /// The group's display name.
    pub display_name: Option<String>,

    /// The group's description, if applicable.
    pub description: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSql, FromSql)]
pub struct Group {
    /// The group's ID.
    pub id: Uuid,

    /// The group's name.
    pub name: String,

    /// The group's display name.
    pub display_name: String,

    /// The group's description, if applicable.
    pub description: Option<String>,

    /// The group's parent resource type.
    pub parent_resource_type: GroupParentResourceType,

    /// The group's parent group ID, if applicable.
    pub parent_group_id: Option<Uuid>,

    /// The group's protected group type, if applicable.
    pub predefined_group_type: Option<PredefinedGroupType>,
}

impl Group {
    /// Counts the number of groups based on a query.
    pub async fn count(
        query: &str,
        database_pool: &deadpool_postgres::Pool,
        principal_type: Option<&AccessPolicyPrincipalType>,
        principal_id: Option<&Uuid>,
    ) -> Result<i64, ResourceError> {
        // Prepare the query.
        let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
            filter: query.to_string(),
            default_limit: None,
            maximum_limit: None,
            should_ignore_limit: true,
            should_ignore_offset: true,
            translate_assignment: Self::translate_assignment,
        };
        let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
        let database_client = database_pool.get().await?;
        let get_resource_action_id: Uuid = database_client
            .query_one(
                "SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'",
                &[&GET_RESOURCE_ACTION_NAME],
            )
            .await?
            .get(0);
        let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(
            &sanitized_filter,
            principal_type,
            principal_id,
            RESOURCE_NAME,
            DATABASE_TABLE_NAME,
            &get_resource_action_id,
            true,
        )?;
        let parsed_parameters = slashstepql::parse_parameters(
            &sanitized_filter.parameters,
            Self::parse_string_slashstepql_parameters,
        )?;
        let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect();

        // Execute the query.
        let rows = database_client.query_one(&query, &parameters).await?;
        let count = rows.get(0);
        Ok(count)
    }

    /// Gets a field by its ID.
    pub async fn get_by_id(
        id: &Uuid,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let database_client = database_pool.get().await?;
        let query = include_str!("../queries/groups/get_group_row_by_id.sql");
        let row = match database_client.query_opt(query, &[&id]).await {
            Ok(row) => match row {
                Some(row) => row,

                None => {
                    return Err(ResourceError::NotFoundError(format!(
                        "A group with the ID \"{}\" does not exist.",
                        id
                    )));
                }
            },

            Err(error) => return Err(ResourceError::PostgresError(error)),
        };

        let field = Self::convert_from_row(&row);

        Ok(field)
    }

    pub async fn get_protected_group_by_type(
        parent_resource_type: &GroupParentResourceType,
        parent_resource_id: Option<&Uuid>,
        predefined_group_type: &PredefinedGroupType,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let database_client = database_pool.get().await?;
        let query = include_str!("../queries/groups/get_group_row_by_protected_group_type.sql");
        let row = match database_client
            .query_opt(
                query,
                &[
                    &predefined_group_type,
                    &parent_resource_type,
                    &parent_resource_id,
                ],
            )
            .await
        {
            Ok(row) => match row {
                Some(row) => row,

                None => {
                    return Err(ResourceError::NotFoundError(format!(
                        "A protected server group with the type \"{}\" does not exist.",
                        predefined_group_type
                    )));
                }
            },

            Err(error) => return Err(ResourceError::PostgresError(error)),
        };

        let group = Self::convert_from_row(&row);

        Ok(group)
    }

    /// Converts a row into a field.
    fn convert_from_row(row: &postgres::Row) -> Self {
        Group {
            id: row.get("id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
            parent_resource_type: row.get("parent_resource_type"),
            parent_group_id: row.get("parent_group_id"),
            predefined_group_type: row.get("predefined_group_type"),
        }
    }

    /// Initializes the groups table.
    pub async fn initialize_resource_table(
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<(), ResourceError> {
        let database_client = database_pool.get().await?;
        let query = include_str!("../queries/groups/initialize_groups_table.sql");
        database_client.execute(query, &[]).await?;
        Ok(())
    }

    /// Creates a new field.
    pub async fn create(
        initial_properties: &InitialGroupProperties,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let query = include_str!("../queries/groups/insert_group_row.sql");
        let parameters: &[&(dyn ToSql + Sync)] = &[
            &initial_properties.name,
            &initial_properties.display_name,
            &initial_properties.description,
            &initial_properties.parent_resource_type,
            &initial_properties.parent_group_id,
            &initial_properties.predefined_group_type,
        ];
        let database_client = database_pool.get().await?;
        let row =
            database_client
                .query_one(query, parameters)
                .await
                .map_err(|error| match error.as_db_error() {
                    Some(db_error) => match db_error.code() {
                        &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError(
                            "A group with the same unique properties already exists.".to_string(),
                        ),

                        _ => ResourceError::PostgresError(error),
                    },

                    None => ResourceError::PostgresError(error),
                })?;

        // Return the app authorization.
        let app_credential = Self::convert_from_row(&row);

        Ok(app_credential)
    }

    /// Deletes this field.
    pub async fn delete(
        &self,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<(), ResourceError> {
        let database_client = database_pool.get().await?;
        let query = include_str!("../queries/groups/delete_group_row_by_id.sql");
        database_client.execute(query, &[&self.id]).await?;
        Ok(())
    }

    /// Returns a list of groups based on a query.
    pub async fn list(
        query: &str,
        database_pool: &deadpool_postgres::Pool,
        principal_type: Option<&AccessPolicyPrincipalType>,
        principal_id: Option<&Uuid>,
    ) -> Result<Vec<Self>, ResourceError> {
        // Prepare the query.
        let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
            filter: query.to_string(),
            default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
            maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
            should_ignore_limit: false,
            should_ignore_offset: false,
            translate_assignment: Self::translate_assignment,
        };
        let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
        let database_client = database_pool.get().await?;
        let get_resource_action_id: Uuid = database_client
            .query_one(
                "SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'",
                &[&GET_RESOURCE_ACTION_NAME],
            )
            .await?
            .get(0);
        let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(
            &sanitized_filter,
            principal_type,
            principal_id,
            RESOURCE_NAME,
            DATABASE_TABLE_NAME,
            &get_resource_action_id,
            false,
        )?;
        let parsed_parameters = slashstepql::parse_parameters(
            &sanitized_filter.parameters,
            Self::parse_string_slashstepql_parameters,
        )?;
        let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect();

        // Execute the query.
        let rows = database_client.query(&query, &parameters).await?;
        let actions = rows.iter().map(Self::convert_from_row).collect();
        Ok(actions)
    }

    /// Parses a string into a parameter for a slashstepql query.
    fn parse_string_slashstepql_parameters<'a>(
        key: &'a str,
        value: &'a str,
    ) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {
        if UUID_QUERY_KEYS.contains(&key) {
            let uuid = match Uuid::parse_str(value) {
                Ok(uuid) => uuid,
                Err(_) => {
                    return Err(SlashstepQLError::StringParserError(format!(
                        "Failed to parse UUID from \"{}\" for key \"{}\".",
                        value, key
                    )));
                }
            };

            return Ok(Box::new(uuid));
        }

        match key {
            "predefined_group_type" => {
                let predefined_group_type = match value {
                    "AnonymousUsers" => PredefinedGroupType::AnonymousUsers,
                    "RegisteredUsers" => PredefinedGroupType::RegisteredUsers,
                    _ => {
                        return Err(SlashstepQLError::StringParserError(format!(
                            "Failed to parse protected group type from \"{}\" for key \"{}\".",
                            value, key
                        )));
                    }
                };

                Ok(Box::new(predefined_group_type))
            }

            _ => Ok(Box::new(value.to_string())),
        }
    }

    fn translate_assignment(
        assignment_properties: SlashstepQLAssignmentProperties,
    ) -> Result<SlashstepQLAssignmentTranslationResult, SlashstepQLError> {
        // TODO: Later, this can be used for parsing in-query functions (i.e. "getCurrentUser()").

        // If the key is already a valid column in the items table, then we can directly translate the assignment without needing to account for dynamic keys.
        if ALLOWED_QUERY_KEYS.contains(&assignment_properties.key.as_str()) {
            return Ok(slashstepql::translate_normal_assignment(
                assignment_properties,
            ));
        }

        Err(SlashstepQLError::InvalidFieldError(
            assignment_properties.key,
        ))
    }

    /// Updates this group and returns a new instance of the group.
    pub async fn update(
        &self,
        properties: &EditableGroupProperties,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let query = String::from("UPDATE groups SET ");
        let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
        let database_client = database_pool.get().await?;

        database_client.query("BEGIN;", &[]).await?;
        let (parameter_boxes, query) = slashstepql::add_parameter_to_query(
            parameter_boxes,
            query,
            "name",
            properties.name.as_ref(),
        );
        let (parameter_boxes, query) = slashstepql::add_parameter_to_query(
            parameter_boxes,
            query,
            "display_name",
            properties.display_name.as_ref(),
        );
        let (parameter_boxes, query) = slashstepql::add_parameter_to_query(
            parameter_boxes,
            query,
            "description",
            properties.description.as_ref(),
        );
        let (mut parameter_boxes, mut query) = (parameter_boxes, query);

        query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
        parameter_boxes.push(Box::new(&self.id));
        let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let row = database_client.query_one(&query, &parameters).await?;
        database_client.query("COMMIT;", &[]).await?;

        let group = Self::convert_from_row(&row);
        Ok(group)
    }
}
