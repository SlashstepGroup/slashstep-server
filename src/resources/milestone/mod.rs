use postgres::error::SqlState;
use postgres_types::{FromSql, ToSql};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum MilestoneError {
  #[error("Couldn't find a milestone with the ID \"{0}\".")]
  NotFoundError(Uuid),

  #[error("A milestone with the name \"{0}\" already exists.")]
  ConflictError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

#[derive(Debug, PartialEq, Eq, ToSql, FromSql, Clone)]
#[postgres(name = "milestone_parent_resource_type")]
pub enum MilestoneParentResourceType {
  Project,
  Workspace
}

#[derive(Debug)]
pub struct Milestone {

  /// The milestone's ID.
  pub id: Uuid,

  /// The milestone's name.
  pub name: String,

  /// The milestone's display name.
  pub display_name: String,

  /// The milestone's description.
  pub description: String,

  pub parent_resource_type: MilestoneParentResourceType,

  /// The milestone's workspace ID.
  pub parent_workspace_id: Option<Uuid>,

  /// The milestone's project ID.
  pub parent_project_id: Option<Uuid>

}

pub struct InitialMilestoneProperties {

  /// The milestone's name.
  pub name: String,

  /// The milestone's display name.
  pub display_name: String,

  /// The milestone's description.
  pub description: String,

  /// The milestone's parent resource type.
  pub parent_resource_type: MilestoneParentResourceType,

  /// The milestone's workspace ID.
  pub parent_workspace_id: Option<Uuid>,

  /// The milestone's project ID.
  pub parent_project_id: Option<Uuid>

}

impl Milestone {

  /// Initializes the milestones table.
  pub async fn initialize_milestones_table(postgres_client: &deadpool_postgres::Client) -> Result<(), MilestoneError> {

    let query = include_str!("../../queries/milestones/initialize-milestones-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  fn from_row(row: &postgres::Row) -> Self {

    return Milestone {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_workspace_id: row.get("parent_workspace_id"),
      parent_project_id: row.get("parent_project_id")
    };

  }

  pub async fn create(initial_properties: &InitialMilestoneProperties, postgres_client: &deadpool_postgres::Client) -> Result<Self, MilestoneError> {

    let query = include_str!("../../queries/milestones/insert-milestone-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_workspace_id,
      &initial_properties.parent_project_id
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => MilestoneError::ConflictError(initial_properties.name.clone()),
        
        _ => MilestoneError::PostgresError(error)

      },

      None => MilestoneError::PostgresError(error)

    })?;

    // Return the milestone.
    let milestone = Milestone::from_row(&row);

    return Ok(milestone);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<Self, MilestoneError> {

    let query = include_str!("../../queries/milestones/get-milestone-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(MilestoneError::NotFoundError(id.clone()))

      },

      Err(error) => return Err(MilestoneError::PostgresError(error))

    };

    let milestone = Milestone::from_row(&row);

    return Ok(milestone);

  }

}