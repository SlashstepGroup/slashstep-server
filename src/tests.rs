use std::{sync::Arc};

use anyhow::{Result};
use chrono::{Duration, Utc};
use deadpool_postgres::tokio_postgres;
use local_ip_address::local_ip;
use postgres::NoTls;
use testcontainers_modules::{testcontainers::runners::AsyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;

use crate::{DEFAULT_MAXIMUM_POSTGRES_CONNECTION_COUNT, import_env_file, initialize_required_tables, resources::{access_policy::{AccessPolicy, InitialAccessPolicyProperties}, action::{Action, InitialActionProperties}, session::{InitialSessionProperties, Session}, user::{InitialUserProperties, User}}};

pub struct TestEnvironment {

  pub postgres_pool: Arc<deadpool_postgres::Pool>,

  // This is required to prevent the compiler from complaining about unused fields.
  // We need a wrapper struct to fix lifetime issues, but we don't need to use the container for any test right now.
  #[allow(dead_code)]
  pub postgres_container: testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>

}

impl TestEnvironment {

  pub async fn new() -> Result<Self> {

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

  pub async fn create_random_action(&self) -> Result<Action> {

    let action_properties = InitialActionProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      app_id: None
    };

    let mut postgres_client = self.postgres_pool.get().await?;

    let action = Action::create(&action_properties, &mut postgres_client).await?;

    return Ok(action);

  }

  pub async fn create_random_user(&self) -> Result<User> {

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

  pub async fn initialize_required_tables(&self) -> Result<()> {

    let mut postgres_client = self.postgres_pool.get().await?;

    initialize_required_tables(&mut postgres_client).await?;

    return Ok(());

  }

  pub async fn create_session(&self, user_id: &Uuid) -> Result<Session> {

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

  pub async fn create_random_access_policy(&self) -> Result<AccessPolicy> {

    let action = self.create_random_action().await?;
    let user = self.create_random_user().await?;
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: crate::resources::access_policy::AccessPolicyPermissionLevel::User,
      inheritance_level: crate::resources::access_policy::AccessPolicyInheritanceLevel::Enabled,
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