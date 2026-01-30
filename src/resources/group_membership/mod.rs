use uuid::Uuid;
use postgres_types::{FromSql, ToSql};
use crate::resources::ResourceError;

#[derive(Debug, Clone, ToSql, FromSql)]
#[postgres(name = "group_membership_principal_type")]
pub enum GroupMembershipPrincipalType {
  App,
  Group,
  User
}

#[derive(Debug, Clone)]
pub struct GroupMembership {

  /// The ID of the group membership.
  pub id: Uuid,

  /// The ID of the group.
  pub group_id: Uuid,

  /// The ID of the principal.
  pub principal_id: Uuid,

  /// The type of the principal.
  pub principal_type: GroupMembershipPrincipalType,

  /// The ID of the principal user, if applicable.
  pub principal_user_id: Option<Uuid>,

  /// The ID of the principal group, if applicable.
  pub principal_group_id: Option<Uuid>,

  /// The ID of the principal app, if applicable.
  pub principal_app_id: Option<Uuid>

}

impl GroupMembership {

  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/group_memberships/get_group_membership_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let app_authorization = GroupMembership::from_row(&row);

    return Ok(app_authorization);

  }

  fn from_row(row: &postgres::Row) -> Self {

    return GroupMembership {
      id: row.get("id"),
      group_id: row.get("group_id"),
      principal_id: row.get("principal_id"),
      principal_type: row.get("principal_type"),
      principal_user_id: row.get("principal_user_id"),
      principal_group_id: row.get("principal_group_id"),
      principal_app_id: row.get("principal_app_id")
    };

  }

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/group_memberships/initialize_group_memberships_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

}