use thiserror::Error;
use crate::{resources::access_policy::IndividualPrincipal, utilities::slashstepql::SlashstepQLError};

pub mod access_policy;
pub mod action;
pub mod action_log_entry;
pub mod app_authorization_credential;
pub mod app_authorization;
pub mod app_credential;
pub mod app;
pub mod group;
pub mod group_membership;
pub mod item;
pub mod milestone;
pub mod project;
pub mod role;
pub mod user;
pub mod workspace;
pub mod server_log_entry;
pub mod http_transaction;
pub mod session;
pub mod role_memberships;

#[derive(Debug, Error)]
pub enum ResourceError {
  #[error("Unexpected enum variant: {0}")]
  UnexpectedEnumVariantError(String),

  #[error("{0}")]
  HierarchyResourceIDMissingError(String),

  #[error("{0}")]
  ConflictError(String),

  #[error(transparent)]
  UUIDError(#[from] uuid::Error),

  #[error("{0}")]
  NotFoundError(String),

  #[error(transparent)]
  SlashstepQLError(#[from] SlashstepQLError),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  DeadpoolPoolError(#[from] deadpool_postgres::PoolError),

  #[error(transparent)]
  VarError(#[from] std::env::VarError),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  JSONWebTokenError(#[from] jsonwebtoken::errors::Error)
}

pub trait SearchableResource<ResourceStruct> {
  fn count(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> impl Future<Output = Result<i64, ResourceError>>;
  fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> impl Future<Output = Result<Vec<ResourceStruct>, ResourceError>>;
}

pub trait DeletableResource {
  fn delete(&self, database_pool: &deadpool_postgres::Pool) -> impl Future<Output = Result<(), ResourceError>>;
}