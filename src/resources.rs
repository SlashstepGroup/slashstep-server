use chrono::{DateTime, Utc};
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::{resources::access_policy::IndividualPrincipal, utilities::slashstepql::SlashstepQLError};

pub mod access_policy;
pub mod action;
pub mod action_log_entry;
pub mod app_authorization_credential;
pub mod app_authorization;
pub mod app_credential;
pub mod app;
pub mod configuration;
pub mod delegation_policy;
pub mod field;
pub mod field_choice;
pub mod field_value;
pub mod group;
pub mod membership;
pub mod http_transaction;
pub mod item;
pub mod item_connection;
pub mod item_connection_type;
pub mod milestone;
pub mod oauth_authorization;
pub mod project;
pub mod role;
pub mod server_log_entry;
pub mod session;
pub mod user;
pub mod view;
pub mod workspace;

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default)]
#[postgres(name = "stakeholder_type")]
pub enum StakeholderType {
  #[default]
  User,
  Group,
  App
}

#[derive(Debug, Error)]
pub enum ResourceError {
  #[error("Unexpected enum variant: {0}")]
  UnexpectedEnumVariantError(String),

  #[error("{0}")]
  HierarchyResourceIDMissingError(String),

  #[error("{0}")]
  ConflictError(String),

  #[error("{0} is an unacceptable date.")]
  DateError(DateTime<Utc>),

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
