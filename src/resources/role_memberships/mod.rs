use std::str::FromStr;
use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use uuid::Uuid;
use crate::{resources::ResourceError, utilities::slashstepql::{SlashstepQLFilterSanitizer, SlashstepQLParameterType, SlashstepQLSanitizeFunctionOptions}};

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

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "User" => Ok(RoleMembershipPrincipalType::User),
      "Group" => Ok(RoleMembershipPrincipalType::Group),
      "App" => Ok(RoleMembershipPrincipalType::App),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }

  }

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

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/role-memberships/get-role-membership-row-by-id.sql");
    let database_client = database_pool.get().await?;
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A role membership with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

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

  pub async fn initialize_role_memberships_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/role-memberships/initialize-role-memberships-table.sql");
    database_client.execute(query, &[]).await?;

    let query = include_str!("../../queries/role-memberships/initialize-hydrated-role-memberships-view.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn parse_slashstepql_parameters(slashstepql_parameters: &Vec<(String, SlashstepQLParameterType)>) -> Result<Vec<Box<dyn ToSql + Sync + Send + '_>>, ResourceError> {

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

  pub async fn list(filter: &str, database_pool: &deadpool_postgres::Pool) -> Result<Vec<Self>, ResourceError> {
                            
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
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let role_memberships: Vec<RoleMembership> = rows.iter().map(RoleMembership::convert_from_row).collect();
    return Ok(role_memberships);

  }

  pub async fn create<'a>(initial_properties: &InitialRoleMembershipProperties<'a>, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = include_str!("../../queries/role-memberships/insert-role-membership-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.role_id,
      &initial_properties.principal_type,
      &initial_properties.principal_user_id,
      &initial_properties.principal_group_id,
      &initial_properties.principal_app_id
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => ResourceError::ConflictError(format!("A role membership with the role ID \"{}\" already exists.", initial_properties.role_id)),
        
        _ => ResourceError::PostgresError(error)

      },

      None => ResourceError::PostgresError(error)

    })?;

    // Return the role membership.
    let role_membership = RoleMembership::convert_from_row(&row);

    return Ok(role_membership);

  }

}