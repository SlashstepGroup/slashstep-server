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
pub mod membership_invitation;
pub mod http_transaction;
pub mod item;
pub mod item_connection;
pub mod item_connection_type;
pub mod item_type;
pub mod item_type_icon;
pub mod iteration;
pub mod milestone;
pub mod oauth_authorization;
pub mod project;
pub mod role;
pub mod server_log_entry;
pub mod session;
pub mod status;
pub mod user;
pub mod view;
pub mod view_field;
pub mod webhook;
pub mod workspace;

use core::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::{utilities::slashstepql::SlashstepQLError};

#[derive(Debug, Clone, ToSql, FromSql, Serialize, Deserialize, PartialEq, Eq, Default, Copy)]
#[postgres(name = "stakeholder_type")]
pub enum StakeholderType {
  #[default]
  User,
  Group,
  App
}

#[derive(Debug, Clone, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize, Default, Copy)]
#[postgres(name = "resource_type")]
pub enum ResourceType {
  AccessPolicy,
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Configuration,
  DelegationPolicy,
  FieldValue,
  Field,
  FieldChoice,
  Group,
  HTTPTransaction,
  Item,
  ItemConnection,
  ItemConnectionType,
  ItemType,
  ItemTypeIcon,
  Iteration,
  Membership,
  MembershipInvitation,
  Milestone,
  OAuthAuthorization,
  Project,
  Role,
  #[default]
  Server,
  ServerLogEntry,
  Session,
  Status,
  User,
  View,
  ViewField,
  Webhook,
  Workspace
}

impl fmt::Display for ResourceType {

  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {

    match self {

      ResourceType::AccessPolicy => write!(formatter, "AccessPolicy"),
      ResourceType::Action => write!(formatter, "Action"),
      ResourceType::ActionLogEntry => write!(formatter, "ActionLogEntry"),
      ResourceType::App => write!(formatter, "App"),
      ResourceType::AppAuthorization => write!(formatter, "AppAuthorization"),
      ResourceType::AppAuthorizationCredential => write!(formatter, "AppAuthorizationCredential"),
      ResourceType::AppCredential => write!(formatter, "AppCredential"),
      ResourceType::Configuration => write!(formatter, "Configuration"),
      ResourceType::DelegationPolicy => write!(formatter, "DelegationPolicy"),
      ResourceType::Field => write!(formatter, "Field"),
      ResourceType::FieldChoice => write!(formatter, "FieldChoice"),
      ResourceType::FieldValue => write!(formatter, "FieldValue"),
      ResourceType::Group => write!(formatter, "Group"),
      ResourceType::HTTPTransaction => write!(formatter, "HTTPTransaction"),
      ResourceType::Server => write!(formatter, "Server"),
      ResourceType::Item => write!(formatter, "Item"),
      ResourceType::ItemConnection => write!(formatter, "ItemConnection"),
      ResourceType::ItemConnectionType => write!(formatter, "ItemConnectionType"),
      ResourceType::ItemType => write!(formatter, "ItemType"),
      ResourceType::ItemTypeIcon => write!(formatter, "ItemTypeIcon"),
      ResourceType::Iteration => write!(formatter, "Iteration"),
      ResourceType::Membership => write!(formatter, "Membership"),
      ResourceType::MembershipInvitation => write!(formatter, "MembershipInvitation"),
      ResourceType::Milestone => write!(formatter, "Milestone"),
      ResourceType::OAuthAuthorization => write!(formatter, "OAuthAuthorization"),
      ResourceType::Project => write!(formatter, "Project"),
      ResourceType::Role => write!(formatter, "Role"),
      ResourceType::ServerLogEntry => write!(formatter, "ServerLogEntry"),
      ResourceType::Session => write!(formatter, "Session"),
      ResourceType::Status => write!(formatter, "Status"),
      ResourceType::User => write!(formatter, "User"),
      ResourceType::View => write!(formatter, "View"),
      ResourceType::ViewField => write!(formatter, "ViewField"),
      ResourceType::Webhook => write!(formatter, "Webhook"),
      ResourceType::Workspace => write!(formatter, "Workspace")

    }

  }
  
}

impl FromStr for ResourceType {

  type Err = ResourceError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {

    match string {
      "AccessPolicy" => Ok(ResourceType::AccessPolicy),
      "Action" => Ok(ResourceType::Action),
      "ActionLogEntry" => Ok(ResourceType::ActionLogEntry),
      "App" => Ok(ResourceType::App),
      "AppAuthorization" => Ok(ResourceType::AppAuthorization),
      "AppAuthorizationCredential" => Ok(ResourceType::AppAuthorizationCredential),
      "AppCredential" => Ok(ResourceType::AppCredential),
      "Configuration" => Ok(ResourceType::Configuration),
      "DelegationPolicy" => Ok(ResourceType::DelegationPolicy),
      "Field" => Ok(ResourceType::Field),
      "FieldChoice" => Ok(ResourceType::FieldChoice),
      "FieldValue" => Ok(ResourceType::FieldValue),
      "Group" => Ok(ResourceType::Group),
      "HTTPTransaction" => Ok(ResourceType::HTTPTransaction),
      "Server" => Ok(ResourceType::Server),
      "Item" => Ok(ResourceType::Item),
      "ItemConnection" => Ok(ResourceType::ItemConnection),
      "ItemConnectionType" => Ok(ResourceType::ItemConnectionType),
      "ItemType" => Ok(ResourceType::ItemType),
      "ItemTypeIcon" => Ok(ResourceType::ItemTypeIcon),
      "Iteration" => Ok(ResourceType::Iteration),
      "Membership" => Ok(ResourceType::Membership),
      "MembershipInvitation" => Ok(ResourceType::MembershipInvitation),
      "Milestone" => Ok(ResourceType::Milestone),
      "OAuthAuthorization" => Ok(ResourceType::OAuthAuthorization),
      "Project" => Ok(ResourceType::Project),
      "Role" => Ok(ResourceType::Role),
      "ServerLogEntry" => Ok(ResourceType::ServerLogEntry),
      "Session" => Ok(ResourceType::Session),
      "Status" => Ok(ResourceType::Status),
      "User" => Ok(ResourceType::User),
      "View" => Ok(ResourceType::View),
      "ViewField" => Ok(ResourceType::ViewField),
      "Webhook" => Ok(ResourceType::Webhook),
      "Workspace" => Ok(ResourceType::Workspace),
      _ => Err(ResourceError::UnexpectedEnumVariantError(string.to_string()))
    }

  }

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

  #[error("The parent resource of the {0} must be the same as the expected type.")]
  DifferentParentError(String),

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
  JSONWebTokenError(#[from] jsonwebtoken::errors::Error),

  // Can't use the #[from] attribute for this error for some reason.
  #[error("An error occurred while hashing the password using Argon2.")]
  Argon2PasswordHashError(argon2::password_hash::Error)
}
