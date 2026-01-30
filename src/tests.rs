use chrono::{Duration, Utc};
use deadpool_postgres::tokio_postgres;
use ed25519_dalek::{SigningKey, ed25519::signature::rand_core::OsRng, pkcs8::{EncodePublicKey, spki::der::pem::LineEnding}};
use local_ip_address::local_ip;
use postgres::NoTls;
use testcontainers_modules::{testcontainers::runners::AsyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;
use crate::{DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT, SlashstepServerError, import_env_file, resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPermissionLevel, InitialAccessPolicyProperties}, action::{Action, ActionParentResourceType, InitialActionProperties}, action_log_entry::{ActionLogEntry, InitialActionLogEntryProperties}, app::{App, AppClientType, AppParentResourceType, InitialAppProperties}, app_authorization::{AppAuthorization, InitialAppAuthorizationProperties}, app_credential::{AppCredential, InitialAppCredentialProperties}, session::{InitialSessionProperties, Session}, user::{InitialUserProperties, User}}, utilities::resource_hierarchy::ResourceHierarchyError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TestSlashstepServerError {

  #[error(transparent)]
  ResourceError(#[from] ResourceError),

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
  PKCS8Error(#[from] ed25519_dalek::pkcs8::Error),

  #[error(transparent)]
  SPKIError(#[from] ed25519_dalek::pkcs8::spki::Error),

  #[error(transparent)]
  SlashstepServerError(#[from] SlashstepServerError),

  #[error(transparent)]
  AnyhowError(#[from] anyhow::Error),

}

pub struct TestEnvironment {

  pub database_pool: deadpool_postgres::Pool,

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

    let database_pool = deadpool_postgres::Pool::builder(manager).max_size(DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT as usize).build()?;

    let environment = TestEnvironment {
      database_pool: database_pool,
      postgres_container: postgres_container
    };

    return Ok(environment);

  }

  pub async fn create_random_app(&self) -> Result<App, TestSlashstepServerError> {

    let app_properties = InitialAppProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      client_type: AppClientType::Public,
      client_secret_hash: Uuid::now_v7().to_string(),
      parent_resource_type: AppParentResourceType::Instance,
      parent_workspace_id: None,
      parent_user_id: None
    };

    let app = App::create(&app_properties, &self.database_pool).await?;

    return Ok(app);

  }
  
  pub async fn create_random_action(&self, parent_app_id: &Option<Uuid>) -> Result<Action, TestSlashstepServerError> {

    let action_properties = InitialActionProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      parent_app_id: parent_app_id.clone(),
      parent_resource_type: if parent_app_id.is_some() { ActionParentResourceType::App } else { ActionParentResourceType::Instance }
    };

    let action = Action::create(&action_properties, &self.database_pool).await?;

    return Ok(action);

  }

  pub async fn create_random_app_authorization(&self, app_id: &Option<Uuid>) -> Result<AppAuthorization, TestSlashstepServerError> {

    // Create a random app.
    let app_id = app_id.unwrap_or(self.create_random_app().await?.id);
    let app_authorization_properties = InitialAppAuthorizationProperties {
      app_id,
      ..Default::default()
    };

    let app_authorization = AppAuthorization::create(&app_authorization_properties, &self.database_pool).await?;

    return Ok(app_authorization);

  }

  pub async fn create_random_app_credential(&self, app_id: &Option<Uuid>) -> Result<AppCredential, TestSlashstepServerError> {

    // Create a random app.
    let app_id = app_id.unwrap_or(self.create_random_app().await?.id);

    // Create a public key.
    let mut os_rng = OsRng;
    let signing_key = SigningKey::generate(&mut os_rng);
    let public_key = signing_key.verifying_key().to_public_key_pem(LineEnding::LF)?;
    let local_ip = local_ip()?;
    let app_credential_properties = InitialAppCredentialProperties {
      app_id: app_id,
      description: Some(Uuid::now_v7().to_string()),
      expiration_date: Some(Utc::now() + Duration::days(30)),
      creation_ip_address: local_ip,
      public_key: public_key.clone()
    };

    let app_credential = AppCredential::create(&app_credential_properties, &self.database_pool).await?;

    return Ok(app_credential);

  }

  pub async fn create_random_action_log_entry(&self) -> Result<ActionLogEntry, TestSlashstepServerError> {

    let action = self.create_random_action(&None).await?;
    let user = self.create_random_user().await?;

    let action_log_entry_properties = InitialActionLogEntryProperties {
      action_id: action.id,
      actor_user_id: Some(user.id),
      ..Default::default()
    };

    let action_log_entry = ActionLogEntry::create(&action_log_entry_properties, &self.database_pool).await?;

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

    let user = User::create(&user_properties, &self.database_pool).await?;

    return Ok(user);

  }

  pub async fn create_session(&self, user_id: &Uuid) -> Result<Session, TestSlashstepServerError> {

    let local_ip = local_ip()?;

    let session_properties = InitialSessionProperties {
      user_id: user_id,
      expiration_date: &(Utc::now() + Duration::days(30)),
      creation_ip_address: &local_ip
    };

    let session = Session::create(&session_properties, &self.database_pool).await?;

    return Ok(session);

  }

  pub async fn create_random_access_policy(&self) -> Result<AccessPolicy, TestSlashstepServerError> {

    let action = self.create_random_action(&None).await?;
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

    let access_policy = AccessPolicy::create(&access_policy_properties, &self.database_pool).await?;

    return Ok(access_policy);

  }

  pub async fn create_instance_access_policy(&self, user_id: &Uuid, action_id: &Uuid, permission_level: &AccessPolicyPermissionLevel) -> Result<AccessPolicy, TestSlashstepServerError> {

    let access_policy = AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: action_id.clone(),
      permission_level: permission_level.clone(),
      is_inheritance_enabled: true,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user_id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Instance,
      ..Default::default()
    }, &self.database_pool).await?;

    return Ok(access_policy);

  }

}