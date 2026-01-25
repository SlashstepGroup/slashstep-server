use crate::{initialize_required_tables, resources::action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryError, InitialActionLogEntryProperties}, tests::{TestEnvironment, TestSlashstepServerError}};

fn assert_action_log_entry_is_equal_to_initial_properties(action_log_entry: &ActionLogEntry, initial_properties: &InitialActionLogEntryProperties) {

  assert_eq!(action_log_entry.action_id, initial_properties.action_id);
  assert_eq!(action_log_entry.actor_type, initial_properties.actor_type);
  assert_eq!(action_log_entry.actor_user_id, initial_properties.actor_user_id);
  assert_eq!(action_log_entry.actor_app_id, initial_properties.actor_app_id);
  assert_eq!(action_log_entry.target_resource_type, initial_properties.target_resource_type);
  assert_eq!(action_log_entry.target_action_id, initial_properties.target_action_id);
  assert_eq!(action_log_entry.target_action_log_entry_id, initial_properties.target_action_log_entry_id);
  assert_eq!(action_log_entry.target_app_id, initial_properties.target_app_id);
  assert_eq!(action_log_entry.target_app_authorization_id, initial_properties.target_app_authorization_id);
  assert_eq!(action_log_entry.target_app_authorization_credential_id, initial_properties.target_app_authorization_credential_id);
  assert_eq!(action_log_entry.target_app_credential_id, initial_properties.target_app_credential_id);
  assert_eq!(action_log_entry.target_group_id, initial_properties.target_group_id);
  assert_eq!(action_log_entry.target_group_membership_id, initial_properties.target_group_membership_id);
  assert_eq!(action_log_entry.target_http_transaction_id, initial_properties.target_http_transaction_id);
  assert_eq!(action_log_entry.target_item_id, initial_properties.target_item_id);
  assert_eq!(action_log_entry.target_milestone_id, initial_properties.target_milestone_id);
  assert_eq!(action_log_entry.target_project_id, initial_properties.target_project_id);
  assert_eq!(action_log_entry.target_role_id, initial_properties.target_role_id);
  assert_eq!(action_log_entry.target_role_membership_id, initial_properties.target_role_membership_id);
  assert_eq!(action_log_entry.target_server_log_entry_id, initial_properties.target_server_log_entry_id);
  assert_eq!(action_log_entry.target_session_id, initial_properties.target_session_id);
  assert_eq!(action_log_entry.target_user_id, initial_properties.target_user_id);
  assert_eq!(action_log_entry.target_workspace_id, initial_properties.target_workspace_id);
  assert_eq!(action_log_entry.reason, initial_properties.reason);

}

/// Verifies that an action log entry can be created.
#[tokio::test]
async fn verify_action_log_entry_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;

  // Create the access policy.
  let action = test_environment.create_random_action().await?;
  let user = test_environment.create_random_user().await?;
  let action_log_entry_properties = InitialActionLogEntryProperties {
    action_id: action.id,
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    ..Default::default()
  };
  let access_policy = ActionLogEntry::create(&action_log_entry_properties, &mut postgres_client).await?;

  // Ensure that all the properties were set correctly.
  assert_action_log_entry_is_equal_to_initial_properties(&access_policy, &action_log_entry_properties);

  return Ok(());

}

/// Verifies that an action log entry can be deleted by its ID.
#[tokio::test]
async fn verify_action_log_entry_deletion_by_id() -> Result<(), TestSlashstepServerError> {

  // Create the access policy.
  let test_environment = TestEnvironment::new().await?;
  let mut postgres_client = test_environment.postgres_pool.get().await?;
  initialize_required_tables(&mut postgres_client).await?;
  let created_action_log_entry = test_environment.create_random_action_log_entry().await?;

  created_action_log_entry.delete(&mut postgres_client).await?;

  // Ensure that the access policy is no longer in the database.
  match ActionLogEntry::get_by_id(&created_action_log_entry.id, &mut postgres_client).await {

    Ok(_) => panic!("Expected an action log entry not found error."),

    Err(error) => match error {

      ActionLogEntryError::NotFoundError(_) => {},

      error => return Err(TestSlashstepServerError::ActionLogEntryError(error))

    }

  }

  return Ok(());

}