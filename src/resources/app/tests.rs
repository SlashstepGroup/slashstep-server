use uuid::Uuid;
use crate::resources::DeletableResource;

use crate::{initialize_required_tables, resources::app::{App, AppClientType, EditableAppProperties}, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies the list function is accurate.
#[tokio::test]
async fn verify_list_excludes_nonexistent_resources() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&postgres_client).await?;

  let apps = App::list(&format!("id = '{}'", Uuid::now_v7().to_string()), &postgres_client, None).await?;
  assert_eq!(apps.len(), 0);

  return Ok(());

}

/// Verifies the update function updates the app and returns the updated app.
#[tokio::test]
async fn verify_update() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;

  // Create the app and update everything.
  let postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&postgres_client).await?;
  let original_app = test_environment.create_random_app().await?;
  let new_name = Uuid::now_v7().to_string();
  let new_display_name = Uuid::now_v7().to_string();
  let new_description = Some(Uuid::now_v7().to_string());
  let new_client_type = AppClientType::Confidential;
  let updated_app = original_app.update(&EditableAppProperties {
    name: Some(new_name.clone()),
    display_name: Some(new_display_name.clone()),
    description: new_description.clone(),
    client_type: Some(new_client_type.clone())
  }, &postgres_client).await?;

  // Verify the new action.
  assert_eq!(original_app.id, updated_app.id);
  assert_eq!(updated_app.name, new_name);
  assert_eq!(updated_app.display_name, new_display_name);
  assert_eq!(updated_app.description, new_description);
  assert_eq!(updated_app.client_type, new_client_type);
  assert_eq!(original_app.parent_resource_type, updated_app.parent_resource_type);
  assert_eq!(original_app.parent_workspace_id, updated_app.parent_workspace_id);
  assert_eq!(original_app.parent_user_id, updated_app.parent_user_id);

  return Ok(());

}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  let postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&postgres_client).await?;
  let created_app = test_environment.create_random_app().await?;

  created_app.delete(&postgres_client).await?;

  // Ensure that the access policy is no longer in the database.
  let retrieved_action_result = App::get_by_id(&created_app.id, &postgres_client).await;
  assert!(retrieved_action_result.is_err());

  return Ok(());

}