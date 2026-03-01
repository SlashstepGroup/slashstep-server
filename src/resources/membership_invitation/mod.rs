#[cfg(test)]
mod tests;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal, membership::{MembershipParentResourceType, MembershipPrincipalType}}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_resource_type",
  "parent_group_id",
  "parent_role_id",
  "invitee_principal_type",
  "invitee_principal_user_id",
  "invitee_principal_group_id",
  "invitee_principal_app_id",
  "inviter_principal_type",
  "inviter_principal_user_id",
  "inviter_principal_app_id"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "parent_group_id",
  "parent_role_id",
  "invitee_principal_user_id",
  "invitee_principal_group_id",
  "invitee_principal_app_id",
  "inviter_principal_user_id",
  "inviter_principal_app_id"
];
pub const RESOURCE_NAME: &str = "MembershipInvitation";
pub const DATABASE_TABLE_NAME: &str = "membership_invitations";
pub const GET_RESOURCE_ACTION_NAME: &str = "membershipInvitations.get";

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default, Copy)]
#[postgres(name = "membership_invitation_invitee_principal_type")]
pub enum MembershipInvitationInviteePrincipalType {
  #[default]
  User,
  App
}

impl FromStr for MembershipInvitationInviteePrincipalType {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "User" => Ok(MembershipInvitationInviteePrincipalType::User),
      "App" => Ok(MembershipInvitationInviteePrincipalType::App),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }
    
  }

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InitialMembershipInvitationProperties {

  /// The membership invitation's parent resource type.
  pub parent_resource_type: MembershipParentResourceType,

  /// The membership invitation's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,

  /// The membership invitation's parent role ID, if applicable.
  pub parent_role_id: Option<Uuid>,

  /// The membership invitation's invitee principal type.
  pub invitee_principal_type: MembershipInvitationInviteePrincipalType,

  /// The membership invitation's invitee principal user ID, if applicable.
  pub invitee_principal_user_id: Option<Uuid>,

  /// The membership invitation's invitee principal group ID, if applicable.
  pub invitee_principal_group_id: Option<Uuid>,

  /// The membership invitation's invitee principal app ID, if applicable.
  pub invitee_principal_app_id: Option<Uuid>,

  /// The membership invitation's inviter principal type.
  pub inviter_principal_type: MembershipPrincipalType,

  /// The membership invitation's inviter principal user ID, if applicable.
  pub inviter_principal_user_id: Option<Uuid>,

  /// The membership invitation's inviter principal app ID, if applicable.
  pub inviter_principal_app_id: Option<Uuid>,

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InitialMembershipInvitationPropertiesWithPredefinedParentAndInviter {

  /// The membership invitation's invitee principal type.
  pub invitee_principal_type: MembershipInvitationInviteePrincipalType,

  /// The membership invitation's invitee principal user ID, if applicable.
  pub invitee_principal_user_id: Option<Uuid>,

  /// The membership invitation's invitee principal group ID, if applicable.
  pub invitee_principal_group_id: Option<Uuid>,

  /// The membership invitation's invitee principal app ID, if applicable.
  pub invitee_principal_app_id: Option<Uuid>,

}

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipInvitation {

  /// The membership invitation's ID.
  pub id: Uuid,

  /// The membership invitation's parent resource type.
  pub parent_resource_type: MembershipParentResourceType,

  /// The membership invitation's parent group ID, if applicable.
  pub parent_group_id: Option<Uuid>,

  /// The membership invitation's parent role ID, if applicable.
  pub parent_role_id: Option<Uuid>,

  /// The membership invitation's invitee principal type.
  pub invitee_principal_type: MembershipInvitationInviteePrincipalType,

  /// The membership invitation's invitee principal user ID, if applicable.
  pub invitee_principal_user_id: Option<Uuid>,

  /// The membership invitation's invitee principal group ID, if applicable.
  pub invitee_principal_group_id: Option<Uuid>,

  /// The membership invitation's invitee principal app ID, if applicable.
  pub invitee_principal_app_id: Option<Uuid>,

  /// The membership invitation's inviter principal type.
  pub inviter_principal_type: MembershipPrincipalType,

  /// The membership invitation's inviter principal user ID, if applicable.
  pub inviter_principal_user_id: Option<Uuid>,

  /// The membership invitation's inviter principal app ID, if applicable.
  pub inviter_principal_app_id: Option<Uuid>

}

impl MembershipInvitation {

  /// Counts the number of item connection types based on a query.
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
    let query = include_str!("../../queries/membership_invitations/get_membership_invitation_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A membership invitation with the ID \"{}\" does not exist.", id)))

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
      parent_resource_type: row.get("parent_resource_type"),
      parent_group_id: row.get("parent_group_id"),
      parent_role_id: row.get("parent_role_id"),
      invitee_principal_type: row.get("invitee_principal_type"),
      invitee_principal_user_id: row.get("invitee_principal_user_id"),
      invitee_principal_group_id: row.get("invitee_principal_group_id"),
      invitee_principal_app_id: row.get("invitee_principal_app_id"),
      inviter_principal_type: row.get("inviter_principal_type"),
      inviter_principal_user_id: row.get("inviter_principal_user_id"),
      inviter_principal_app_id: row.get("inviter_principal_app_id")
    };

  }

  /// Initializes the memberships table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/membership_invitations/initialize_membership_invitations_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new field.
  pub async fn create(initial_properties: &InitialMembershipInvitationProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/membership_invitations/insert_membership_invitation_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.parent_resource_type,
      &initial_properties.parent_group_id,
      &initial_properties.parent_role_id,
      &initial_properties.invitee_principal_type,
      &initial_properties.invitee_principal_user_id,
      &initial_properties.invitee_principal_group_id,
      &initial_properties.invitee_principal_app_id,
      &initial_properties.inviter_principal_type,
      &initial_properties.inviter_principal_user_id,
      &initial_properties.inviter_principal_app_id
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

    match key {

      "parent_resource_type" => {

        let parent_resource_type = match MembershipParentResourceType::from_str(value) {
          Ok(parent_resource_type) => parent_resource_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))
        };

        return Ok(Box::new(parent_resource_type));

      },

      "invitee_principal_type" => {

        let principal_type = match MembershipInvitationInviteePrincipalType::from_str(value) {
          Ok(principal_type) => principal_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))
        };

        return Ok(Box::new(principal_type));

      },

      "inviter_principal_type" => {

        let inviter_principal_type = match MembershipPrincipalType::from_str(value) {
          Ok(inviter_principal_type) => inviter_principal_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))
        };

        return Ok(Box::new(inviter_principal_type));

      },

      _ => return Ok(Box::new(value))

    }

  }

  /// Returns a list of memberships based on a query.
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

impl DeletableResource for MembershipInvitation {

  /// Deletes this field.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/membership_invitations/delete_membership_invitation_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}