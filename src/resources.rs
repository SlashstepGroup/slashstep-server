use thiserror::Error;

use crate::utilities::slashstepql::SlashstepQLError;

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
  PostgresError(#[from] postgres::Error)
}