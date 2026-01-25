use std::{sync::Arc};
use chrono::{Duration, Utc};
use deadpool_postgres::tokio_postgres;
use local_ip_address::local_ip;
use postgres::NoTls;
use testcontainers_modules::{testcontainers::runners::AsyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;
use crate::{DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT, SlashstepServerError, import_env_file, resources::{access_policy::{AccessPolicy, AccessPolicyError, InitialAccessPolicyProperties}, action::{Action, ActionError, ActionParentResourceType, InitialActionProperties}, action_log_entry::{ActionLogEntry, ActionLogEntryError, InitialActionLogEntryProperties}, app::AppError, app_authorization::AppAuthorizationError, app_authorization_credential::AppAuthorizationCredentialError, app_credential::AppCredentialError, group::GroupError, group_membership::GroupMembershipError, http_transaction::HTTPTransactionError, item::ItemError, milestone::MilestoneError, project::ProjectError, role::RoleError, role_memberships::RoleMembershipError, server_log_entry::ServerLogEntryError, session::{InitialSessionProperties, Session, SessionError}, user::{InitialUserProperties, User, UserError}, workspace::WorkspaceError}, utilities::resource_hierarchy::ResourceHierarchyError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TestSlashstepServerError {

  #[error(transparent)]
  HTTPTransactionError(#[from] HTTPTransactionError),

  #[error(transparent)]
  UserError(#[from] UserError),

  #[error(transparent)]
  SessionError(#[from] SessionError),

  #[error(transparent)]
  GroupError(#[from] GroupError),

  #[error(transparent)]
  GroupMembershipError(#[from] GroupMembershipError),

  #[error(transparent)]
  AppError(#[from] AppError),

  #[error(transparent)]
  WorkspaceError(#[from] WorkspaceError),

  #[error(transparent)]
  ProjectError(#[from] ProjectError),

  #[error(transparent)]
  RoleError(#[from] RoleError),

  #[error(transparent)]
  ItemError(#[from] ItemError),

  #[error(transparent)]
  ActionError(#[from] ActionError),

  #[error(transparent)]
  ActionLogEntryError(#[from] ActionLogEntryError),

  #[error(transparent)]
  AppAuthorizationError(#[from] AppAuthorizationError),

  #[error(transparent)]
  ServerLogEntryError(#[from] ServerLogEntryError),

  #[error(transparent)]
  AppAuthorizationCredentialError(#[from] AppAuthorizationCredentialError),

  #[error(transparent)]
  AppCredentialError(#[from] AppCredentialError),

  #[error(transparent)]
  MilestoneError(#[from] MilestoneError),

  #[error(transparent)]
  AccessPolicyError(#[from] AccessPolicyError),

  #[error(transparent)]
  RoleMembershipError(#[from] RoleMembershipError),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error),

  #[error(transparent)]
  ParseIntError(#[from] std::num::ParseIntError),

  #[error(transparent)]
  DeadpoolBuildError(#[from] deadpool_postgres::BuildError),

  #[error(transparent)]
  DeadpoolPoolError(#[from] deadpool_postgres::PoolError),

  #[error(transparent)]
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  LocalIPAddressError(#[from] local_ip_address::Error),

  #[error(transparent)]
  ResourceHierarchyError(#[from] ResourceHierarchyError),

  #[error(transparent)]
  TestcontainersError(#[from] testcontainers::TestcontainersError),

  #[error(transparent)]
  SlashstepServerError(#[from] SlashstepServerError),

  #[error(transparent)]
  AnyhowError(#[from] anyhow::Error),

}

pub struct TestEnvironment {

  pub postgres_pool: Arc<deadpool_postgres::Pool>,

  // This is required to prevent the compiler from complaining about unused fields.
  // We need a wrapper struct to fix lifetime issues, but we don't need to use the container for any test right now.
  #[allow(dead_code)]
  pub postgres_container: testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>

}

impl TestEnvironment {

  pub async fn new() -> Result<Self, TestSlashstepServerError> {

    import_env_file();
    
    let postgres_container = testcontainers_modules::postgres::Postgres::default()
      .with_tag("18")
      .start()
      .await?;
    let postgres_host = postgres_container.get_host().await?;
    let postgres_port = postgres_container.get_host_port_ipv4(5432).await?;

    let mut postgres_config = tokio_postgres::Config::new();
    postgres_config.host(postgres_host.to_string());
    postgres_config.port(postgres_port);
    postgres_config.user("postgres");
    postgres_config.password("postgres");
    let manager_config = deadpool_postgres::ManagerConfig {
      recycling_method: deadpool_postgres::RecyclingMethod::Fast
    };
    let manager = deadpool_postgres::Manager::from_config(postgres_config, NoTls, manager_config);

    let postgres_pool = deadpool_postgres::Pool::builder(manager).max_size(DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT as usize).build()?;

    let environment = TestEnvironment {
      postgres_pool: Arc::new(postgres_pool),
      postgres_container: postgres_container
    };

    return Ok(environment);

  }

  pub async fn create_random_action(&self) -> Result<Action, TestSlashstepServerError> {

    let action_properties = InitialActionProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    };

    let mut postgres_client = self.postgres_pool.get().await?;

    let action = Action::create(&action_properties, &mut postgres_client).await?;

    return Ok(action);

  }

  pub async fn create_random_action_log_entry(&self) -> Result<ActionLogEntry, TestSlashstepServerError> {

    let action = self.create_random_action().await?;
    let user = self.create_random_user().await?;

    let mut postgres_client = self.postgres_pool.get().await?;

    let action_log_entry_properties = InitialActionLogEntryProperties {
      action_id: action.id,
      actor_user_id: Some(user.id),
      ..Default::default()
    };

    let action_log_entry = ActionLogEntry::create(&action_log_entry_properties, &mut postgres_client).await?;

    return Ok(action_log_entry);

  }

  pub async fn create_random_user(&self) -> Result<User, TestSlashstepServerError> {

    let user_properties = InitialUserProperties {
      username: Some(Uuid::now_v7().to_string()),
      display_name: Some(Uuid::now_v7().to_string()),
      hashed_password: Some(Uuid::now_v7().to_string()),
      is_anonymous: false,
      ip_address: None
    };

    let mut postgres_client = self.postgres_pool.get().await?;

    let user = User::create(&user_properties, &mut postgres_client).await?;

    return Ok(user);

  }

  pub async fn create_session(&self, user_id: &Uuid) -> Result<Session, TestSlashstepServerError> {

    let local_ip = local_ip()?;

    let session_properties = InitialSessionProperties {
      user_id: user_id,
      expiration_date: &(Utc::now() + Duration::days(30)),
      creation_ip_address: &local_ip
    };

    let mut postgres_client = self.postgres_pool.get().await?;

    let session = Session::create(&session_properties, &mut postgres_client).await?;

    return Ok(session);

  }

  pub async fn create_random_access_policy(&self) -> Result<AccessPolicy, TestSlashstepServerError> {

    let action = self.create_random_action().await?;
    let user = self.create_random_user().await?;
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: crate::resources::access_policy::AccessPolicyPermissionLevel::User,
      is_inheritance_enabled: true,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Instance,
      ..Default::default()
    };

    let mut postgres_client = self.postgres_pool.get().await?;

    let access_policy = AccessPolicy::create(&access_policy_properties, &mut postgres_client).await?;

    return Ok(access_policy);

  }

}