DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_log_entry_actor_type') THEN
      CREATE TYPE action_log_entry_actor_type AS ENUM (
        'User',
        'App',
        'Server'
      );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_log_entry_target_resource_type') THEN
      CREATE TYPE action_log_entry_target_resource_type AS ENUM (
        'AccessPolicy',
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'FieldValue',
        'Field',
        'FieldChoice',
        'Group',
        'GroupMembership',
        'HTTPTransaction',
        'Server',
        'Item',
        'Milestone',
        'OAuthAuthorization',
        'Project',
        'Role',
        'RoleMembership',
        'ServerLogEntry',
        'Session',
        'User',
        'Workspace'
      );
    END IF;

    -- There are no references in this table to support logs for deleted resources.
    CREATE TABLE IF NOT EXISTS action_log_entries (
      id UUID default uuidv7() PRIMARY KEY,
      action_id UUID NOT NULL REFERENCES actions(id),
      http_transaction_id UUID,
      actor_type action_log_entry_actor_type not null,
      actor_user_id UUID,
      actor_app_id UUID,
      target_resource_type action_log_entry_target_resource_type not null,
      target_access_policy_id UUID, 
      target_action_id UUID,
      target_action_log_entry_id UUID,
      target_app_id UUID,
      target_app_authorization_id UUID,
      target_app_authorization_credential_id UUID,
      target_app_credential_id UUID,
      target_field_value_id UUID,
      target_field_id UUID,
      target_field_choice_id UUID,
      target_group_id UUID,
      target_group_membership_id UUID,
      target_http_transaction_id UUID,
      target_item_id UUID,
      target_milestone_id UUID,
      target_oauth_authorization_id UUID,
      target_project_id UUID,
      target_role_id UUID,
      target_role_membership_id UUID,
      target_server_log_entry_id UUID,
      target_session_id UUID,
      target_user_id UUID,
      target_workspace_id UUID,
      reason TEXT
    );
  END
$$ LANGUAGE plpgsql;