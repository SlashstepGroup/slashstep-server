use std::str::FromStr;

use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use thiserror::Error;
use uuid::Uuid;

use crate::utilities::slashstepql::{SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParameterType, SlashstepQLSanitizeFunctionOptions};

static ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "role_id",
  "principal_type",
  "principal_user_id",
  "principal_group_id",
  "principal_app_id"
];

const DEFAULT_ROLE_MEMBERSHIP_LIST_LIMIT: i64 = 1000;

const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "role_id",
  "principal_user_id",
  "principal_group_id",
  "principal_app_id"
];

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone)]
#[postgres(name = "role_membership_principal_type")]
pub enum RoleMembershipPrincipalType {
  User,
  Group,
  App
}

impl FromStr for RoleMembershipPrincipalType {

  type Err = RoleMembershipError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "User" => Ok(RoleMembershipPrincipalType::User),
      "Group" => Ok(RoleMembershipPrincipalType::Group),
      "App" => Ok(RoleMembershipPrincipalType::App),
      _ => Err(RoleMembershipError::InvalidPrincipalType(string.to_string()))
    }

  }

}

#[derive(Debug, Error)]
pub enum RoleMembershipError {
  #[error("A role membership with the ID \"{0}\" already exists.")]
  ConflictError(Uuid),

  #[error("Couldn't find a role membership with the ID \"{0}\".")]
  NotFoundError(Uuid),

  #[error("Invalid principal type: {0}")]
  InvalidPrincipalType(String),

  #[error(transparent)]
  UUIDError(#[from] uuid::Error),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  SlashstepQLError(#[from] SlashstepQLError)
}

#[derive(Debug, Clone)]
pub struct RoleMembership {
  pub id: Uuid,
  pub role_id: Uuid,
  pub principal_type: RoleMembershipPrincipalType,
  pub principal_user_id: Option<Uuid>,
  pub principal_group_id: Option<Uuid>,
  pub principal_app_id: Option<Uuid>
}

#[derive(Debug, Clone)]
pub struct InitialRoleMembershipProperties<'a> {
  pub role_id: &'a Uuid,
  pub principal_type: &'a RoleMembershipPrincipalType,
  pub principal_user_id: Option<&'a Uuid>,
  pub principal_group_id: Option<&'a Uuid>,
  pub principal_app_id: Option<&'a Uuid>
}

impl RoleMembership {

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<Self, RoleMembershipError> {

    let query = include_str!("../../queries/role-memberships/get-role-membership-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(RoleMembershipError::NotFoundError(id.clone()))

      },

      Err(error) => return Err(RoleMembershipError::PostgresError(error))

    };

    let role_membership = RoleMembership::convert_from_row(&row);

    return Ok(role_membership);

  }

  pub fn convert_from_row(row: &postgres::Row) -> Self {

    return RoleMembership {
      id: row.get("id"),
      role_id: row.get("role_id"),
      principal_type: row.get("principal_type"),
      principal_user_id: row.get("principal_user_id"),
      principal_group_id: row.get("principal_group_id"),
      principal_app_id: row.get("principal_app_id")
    };

  }

  pub async fn initialize_role_memberships_table(postgres_client: &deadpool_postgres::Client) -> Result<(), RoleMembershipError> {

    let query = include_str!("../../queries/role-memberships/initialize-role-memberships-table.sql");
    postgres_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/role-memberships/initialize-hydrated-role-memberships-view.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn parse_slashstepql_parameters(slashstepql_parameters: &Vec<(String, SlashstepQLParameterType)>) -> Result<Vec<Box<dyn ToSql + Sync + Send + '_>>, RoleMembershipError> {

    // https://users.rust-lang.org/t/axum-tokio-postgres-error-on-using-vec/114024/4
    let mut parameters: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

    for (key, value) in slashstepql_parameters {

      match value {

        SlashstepQLParameterType::String(string_value) => {

          if UUID_QUERY_KEYS.contains(&key.as_str()) {

            let uuid = Uuid::parse_str(string_value)?;
            parameters.push(Box::new(uuid));

          } else {

            match key.as_str() {

              "principal_type" => {

                let principal_type = RoleMembershipPrincipalType::from_str(string_value)?;
                parameters.push(Box::new(principal_type));

              },

              _ => {

                parameters.push(Box::new(string_value));

              }

            }

          }
          
        },

        SlashstepQLParameterType::Number(number_value) => {

          parameters.push(Box::new(number_value));

        },

        SlashstepQLParameterType::Boolean(boolean_value) => {

          parameters.push(Box::new(boolean_value));

        }

      }

    }

    return Ok(parameters);

  }

  pub async fn list(filter: &str, postgres_client: &deadpool_postgres::Client) -> Result<Vec<Self>, RoleMembershipError> {
                            
    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: filter.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_ROLE_MEMBERSHIP_LIST_LIMIT),
      maximum_limit: None,
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let where_clause = sanitized_filter.where_clause.and_then(|string| Some(format!(" where {}", string))).unwrap_or("".to_string());
    let limit_clause = sanitized_filter.limit.and_then(|limit| Some(format!(" limit {}", limit))).unwrap_or("".to_string());
    let offset_clause = sanitized_filter.offset.and_then(|offset| Some(format!(" offset {}", offset))).unwrap_or("".to_string());
    let query = format!("select * from hydrated_role_memberships{}{}{}", where_clause, limit_clause, offset_clause);

    // Execute the query.
    let parsed_parameters = Self::parse_slashstepql_parameters(&sanitized_filter.parameters)?; // This is causing an error in \{access_policy_id}\mod.rs
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = postgres_client.query(&query, &parameters).await?;
    let role_memberships: Vec<RoleMembership> = rows.iter().map(RoleMembership::convert_from_row).collect();
    return Ok(role_memberships);

  }

  pub async fn create<'a>(initial_properties: &InitialRoleMembershipProperties<'a>, postgres_client: &deadpool_postgres::Client) -> Result<Self, RoleMembershipError> {

    let query = include_str!("../../queries/role-memberships/insert-role-membership-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.role_id,
      &initial_properties.principal_type,
      &initial_properties.principal_user_id,
      &initial_properties.principal_group_id,
      &initial_properties.principal_app_id
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => RoleMembershipError::ConflictError(initial_properties.role_id.clone()),
        
        _ => RoleMembershipError::PostgresError(error)

      },

      None => RoleMembershipError::PostgresError(error)

    })?;

    // Return the role membership.
    let role_membership = RoleMembership::convert_from_row(&row);

    return Ok(role_membership);

  }

}