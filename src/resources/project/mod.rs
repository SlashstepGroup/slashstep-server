use chrono::{DateTime, Utc};
use postgres::error::SqlState;
use postgres_types::ToSql;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProjectError {
  #[error("A project with the ID \"{0}\" does not exist.")]
  NotFoundError(String),

  #[error("A project with the name \"{0}\" already exists.")]
  ConflictError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

pub struct InitialProjectProperties<'a> {
  pub name: &'a str,
  pub display_name: &'a str,
  pub description: &'a str,
  pub workspace_id: Uuid,
  pub start_date: Option<&'a DateTime<Utc>>,
  pub end_date: Option<&'a DateTime<Utc>>
}

#[derive(Debug, Clone, Serialize)]
pub struct Project {
  pub id: Uuid,
  pub name: String,
  pub display_name: String,
  pub description: String,
  pub start_date: Option<DateTime<Utc>>,
  pub end_date: Option<DateTime<Utc>>,
  pub workspace_id: Uuid
}

impl Project {

  /// Initializes the projects table.
  pub async fn initialize_projects_table(postgres_client: &deadpool_postgres::Client) -> Result<(), ProjectError> {

    let query = include_str!("../../queries/projects/initialize-projects-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub fn from_row(row: &postgres::Row) -> Self {

    return Project {
      id: row.get("id"),
      name: row.get("name"),
      display_name: row.get("display_name"),
      description: row.get("description"),
      start_date: row.get("start_date"),
      end_date: row.get("end_date"),
      workspace_id: row.get("workspace_id")
    };

  }

  pub async fn create(initial_properties: &InitialProjectProperties<'_>, postgres_client: &deadpool_postgres::Client) -> Result<Self, ProjectError> {

    let query = include_str!("../../queries/projects/insert-project-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.name,
      &initial_properties.display_name,
      &initial_properties.description,
      &initial_properties.start_date,
      &initial_properties.end_date
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => ProjectError::ConflictError(initial_properties.name.to_string()),
        
        _ => ProjectError::PostgresError(error)

      },

      None => ProjectError::PostgresError(error)

    })?;

    // Return the project.
    let project = Project::from_row(&row);

    return Ok(project);

  }

  pub async fn get_by_id(id: &Uuid, postgres_client: &deadpool_postgres::Client) -> Result<Self, ProjectError> {

    let query = include_str!("../../queries/projects/get-project-row-by-id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ProjectError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ProjectError::PostgresError(error))

    };

    let project = Project::from_row(&row);

    return Ok(project);

  }

}