use anyhow::Result;
use deadpool_postgres::tokio_postgres;
use postgres::NoTls;
use testcontainers_modules::{testcontainers::runners::AsyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;

use crate::{resources::{action::{Action, InitialActionProperties}, user::{InitialUserProperties, User}}};

pub struct TestEnvironment {

  pub postgres_pool: deadpool_postgres::Pool,
  
  pub postgres_client: deadpool_postgres::Client,

  // This is required to prevent the compiler from complaining about unused fields.
  // We need a wrapper struct to fix lifetime issues, but we don't need to use the container for any test right now.
  #[allow(dead_code)]
  pub postgres_container: testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>

}

impl TestEnvironment {

  pub async fn new() -> Result<Self> {

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

    let postgres_pool = deadpool_postgres::Pool::builder(manager).max_size(1).build()?;
    let postgres_client = postgres_pool.get().await?;

    let environment = TestEnvironment {
      postgres_pool,
      postgres_client,
      postgres_container: postgres_container
    };

    return Ok(environment);

  }

  pub async fn create_random_action(&mut self) -> Result<Action> {

    let action_properties = InitialActionProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      app_id: None
    };

    let action = Action::create(&action_properties, &mut self.postgres_client).await?;

    return Ok(action);

  }

  pub async fn create_random_user(&mut self) -> Result<User> {

    let user_properties = InitialUserProperties {
      username: Some(Uuid::now_v7().to_string()),
      display_name: Some(Uuid::now_v7().to_string()),
      hashed_password: Some(Uuid::now_v7().to_string()),
      is_anonymous: false,
      ip_address: None
    };

    let user = User::create(&user_properties, &mut self.postgres_client).await?;

    return Ok(user);

  }

}