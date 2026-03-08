/**
 * 
 * This module defines the implementation and types of a webhook.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{ResourceError, access_policy::AccessPolicyPrincipalType}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "display_name",
  "url",
  "is_enabled",
  "parent_resource_type",
  "parent_app_id",
  "parent_group_id",
  "parent_project_id",
  "parent_user_id",
  "parent_workspace_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_app_id",
  "parent_group_id",
  "parent_project_id",
  "parent_user_id",
  "parent_workspace_id"
];
pub const RESOURCE_NAME: &str = "Webhook";
pub const DATABASE_TABLE_NAME: &str = "webhooks";
pub const GET_RESOURCE_ACTION_NAME: &str = "webhooks.get";

#[derive(Debug, Clone, Copy, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "webhook_parent_resource_type")]
pub enum WebhookParentResourceType {
  App,
  Group,
  Project,
  #[default]
  Server,
  User,
  Workspace
}

impl FromStr for WebhookParentResourceType {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {

      "App" => Ok(Self::App),
      "Group" => Ok(Self::Group),
      "Project" => Ok(Self::Project),
      "Server" => Ok(Self::Server),
      "User" => Ok(Self::User),
      "Workspace" => Ok(Self::Workspace),
      string => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))

    }

  }

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InitialWebhookProperties {

  /// The webhook's display name.
  pub display_name: String,

  /// The webhook's URL.
  /// 
  /// Slashstep Server will send a POST request to this URL when the webhook is triggered.
  pub url: String,

  /// The webhook's hashed secret, if applicable. 
  /// 
  /// The receiving end of the webhook can use this hashed secret to verify webhook events come from Slashstep Server. 
  pub hashed_secret: Option<String>,

  /// Whether the webhook is enabled.
  pub is_enabled: bool,

  /// The webhook's parent resource type.
  pub parent_resource_type: WebhookParentResourceType,

  /// The webhook's parent app ID, if applicable.
  pub parent_app_id: Option<Uuid>,

  /// The webhook's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,

  /// The webhook's parent project ID, if applicable.
  pub parent_project_id: Option<Uuid>,

  /// The webhook's parent user ID, if applicable.
  pub parent_user_id: Option<Uuid>,

  /// The webhook's parent workspace ID, if applicable.
  pub parent_workspace_id: Option<Uuid>

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EditableWebhookProperties {

  /// The webhook's display name.
  pub display_name: Option<String>,

  /// The webhook's URL.
  /// 
  /// Slashstep Server will send a POST request to this URL when the webhook is triggered.
  pub url: Option<String>,

  /// The webhook's hashed secret, if applicable. 
  /// 
  /// The receiving end of the webhook can use this hashed secret to verify webhook events come from Slashstep Server. 
  pub hashed_secret: Option<Option<String>>,

  /// Whether the webhook is enabled.
  pub is_enabled: Option<bool>

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct Webhook {

  /// The webhook's ID.
  pub id: Uuid,

  /// The webhook's display name.
  pub display_name: String,

  /// The webhook's URL.
  /// 
  /// Slashstep Server will send a POST request to this URL when the webhook is triggered.
  pub url: String,

  /// The webhook's hashed secret, if applicable. 
  /// 
  /// The receiving end of the webhook can use this hashed secret to verify webhook events come from Slashstep Server.
  /// 
  /// This field is private and should not be returned in public queries.  
  hashed_secret: Option<String>,

  /// Whether the webhook is enabled.
  pub is_enabled: bool,

  /// The webhook's parent resource type.
  pub parent_resource_type: WebhookParentResourceType,

  /// The webhook's parent app ID, if applicable.
  pub parent_app_id: Option<Uuid>,

  /// The webhook's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,

  /// The webhook's parent project ID, if applicable.
  pub parent_project_id: Option<Uuid>,

  /// The webhook's parent user ID, if applicable.
  pub parent_user_id: Option<Uuid>,

  /// The webhook's parent workspace ID, if applicable.
  pub parent_workspace_id: Option<Uuid>

}

impl Webhook {

  /// Counts the number of webhooks based on a query.
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<i64, ResourceError> {

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
    let query = include_str!("../../queries/webhooks/get_webhook_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A field value with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let field = Self::convert_from_row(&row);

    return Ok(field);

  }

  /// Converts a row into a field.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return Self {
      id: row.get("id"),
      display_name: row.get("display_name"),
      url: row.get("url"),
      hashed_secret: row.get("hashed_secret"),
      is_enabled: row.get("is_enabled"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_app_id: row.get("parent_app_id"),
      parent_group_id: row.get("parent_group_id"),
      parent_project_id: row.get("parent_project_id"),
      parent_user_id: row.get("parent_user_id"),
      parent_workspace_id: row.get("parent_workspace_id")
    };

  }

  /// Initializes the webhooks table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/webhooks/initialize_webhooks_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialWebhookProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/webhooks/insert_webhook_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.display_name,
      &initial_properties.url,
      &initial_properties.hashed_secret,
      &initial_properties.is_enabled,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_app_id,
      &initial_properties.parent_group_id,
      &initial_properties.parent_project_id,
      &initial_properties.parent_user_id,
      &initial_properties.parent_workspace_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the app authorization.
    let app_credential = Self::convert_from_row(&row);

    return Ok(app_credential);

  }

  /// Deletes this field.
  pub async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/webhooks/delete_webhook_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

  /// Gets the webhook's hashed secret, if applicable.
  pub fn get_hashed_secret(&self) -> Option<String> {

    return self.hashed_secret.clone();

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

    match key {

      "parent_resource_type" => {

        let parent_resource_type = match WebhookParentResourceType::from_str(value) {

          Ok(parent_resource_type) => parent_resource_type,
          Err(error) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\": {}", value, key, error)))

        };

        return Ok(Box::new(parent_resource_type));

      },

      _ => {}

    }

    return Ok(Box::new(value));

  }

  /// Returns a list of webhooks based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, principal_type: Option<&AccessPolicyPrincipalType>, principal_id: Option<&Uuid>) -> Result<Vec<Self>, ResourceError> {

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

  /// Updates this item and returns a new instance of the item.
  pub async fn update(&self, properties: &EditableWebhookProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("UPDATE webhooks SET ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("BEGIN;", &[]).await?;
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "display_name", properties.display_name.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "url", properties.url.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "hashed_secret", properties.hashed_secret.as_ref());
    let (parameter_boxes, query) = slashstepql::add_parameter_to_query(parameter_boxes, query, "is_enabled", properties.is_enabled.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" WHERE id = ${} RETURNING *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("COMMIT;", &[]).await?;

    let webhook = Self::convert_from_row(&row);
    return Ok(webhook);

  }

}
