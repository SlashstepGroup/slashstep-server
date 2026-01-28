use uuid::Uuid;

use crate::{initialize_required_tables, resources::app::App, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies the list function is accurate.
#[tokio::test]
async fn verify_list_excludes_nonexistent_resources() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;

  let apps = App::list(&format!("id = '{}'", Uuid::now_v7().to_string()), &mut postgres_client, None).await?;
  assert_eq!(apps.len(), 0);

  return Ok(());

}
