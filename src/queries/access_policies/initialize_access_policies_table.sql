DO $$
  BEGIN

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'resource_type') THEN
      CREATE TYPE resource_type AS ENUM (
        'AccessPolicy',
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'Configuration',
        'DelegationPolicy',
        'Field',
        'FieldChoice',
        'FieldValue',
        'Group',
        'HTTPTransaction',
        'Server',
        'Item',
        'ItemConnection',
        'ItemConnectionType',
        'Membership',
        'Milestone',
        'Project',
        'Role',
        'ServerLogEntry',
        'Session',
        'User',
        'View',
        'Workspace'
      );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'access_policy_resource_type') THEN
      CREATE TYPE access_policy_resource_type AS ENUM (
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'Configuration',
        'DelegationPolicy',
        'Field',
        'FieldChoice',
        'FieldValue',
        'Group',
        'HTTPTransaction',
        'Server',
        'Item',
        'ItemConnection',
        'ItemConnectionType',
        'Membership',
        'Milestone',
        'Project',
        'Role',
        'ServerLogEntry',
        'Session',
        'User',
        'View',
        'Workspace'
      );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'principal_type') THEN
      CREATE TYPE principal_type AS ENUM (
        'User',
        'Group',
        'Role',
        'App'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS access_policies (
      id UUID DEFAULT uuidv7() primary key,

      /* Principals */
      principal_type principal_type NOT NULL,
      principal_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      principal_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
      principal_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
      principal_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,

      /* Scopes */
      scoped_resource_type access_policy_resource_type NOT NULL,
      scoped_action_id UUID REFERENCES actions(id) ON DELETE CASCADE,
      scoped_action_log_entry_id UUID REFERENCES action_log_entries(id) ON DELETE CASCADE,
      scoped_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
      scoped_app_authorization_id UUID REFERENCES app_authorizations(id) ON DELETE CASCADE,
      scoped_app_authorization_credential_id UUID REFERENCES app_authorization_credentials(id) ON DELETE CASCADE,
      scoped_app_credential_id UUID REFERENCES app_credentials(id) ON DELETE CASCADE,
      scoped_configuration_id UUID REFERENCES configurations(id) ON DELETE CASCADE,
      scoped_delegation_policy_id UUID REFERENCES delegation_policies(id) ON DELETE CASCADE,
      scoped_field_id UUID REFERENCES fields(id) ON DELETE CASCADE,
      scoped_field_choice_id UUID REFERENCES field_choices(id) ON DELETE CASCADE,
      scoped_field_value_id UUID REFERENCES field_values(id) ON DELETE CASCADE,
      scoped_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
      scoped_http_transaction_id UUID REFERENCES http_transactions(id) ON DELETE CASCADE,
      scoped_item_id UUID REFERENCES items(id) ON DELETE CASCADE,
      scoped_item_connection_id UUID REFERENCES item_connections(id) ON DELETE CASCADE,
      scoped_item_connection_type_id UUID REFERENCES item_connection_types(id) ON DELETE CASCADE,
      scoped_membership_id UUID REFERENCES memberships(id) ON DELETE CASCADE,
      scoped_milestone_id UUID REFERENCES milestones(id) ON DELETE CASCADE,
      scoped_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      scoped_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
      scoped_server_log_entry_id UUID REFERENCES server_log_entries(id) ON DELETE CASCADE,
      scoped_session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
      scoped_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      scoped_view_id UUID REFERENCES views(id) ON DELETE CASCADE,
      scoped_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,

      /* Permissions */
      action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
      permission_level permission_level NOT NULL,
      is_inheritance_enabled BOOLEAN NOT NULL,

      /* Constraints */
      constraint one_principal_type check (
        (principal_type = 'User' and principal_user_id IS NOT NULL and principal_group_id IS NULL and principal_role_id IS NULL and principal_app_id IS NULL)
        or (principal_type = 'Group' and principal_user_id IS NULL and principal_group_id IS NOT NULL and principal_role_id IS NULL and principal_app_id IS NULL)
        or (principal_type = 'Role' and principal_user_id IS NULL and principal_group_id IS NULL and principal_role_id IS NOT NULL and principal_app_id IS NULL)
        or (principal_type = 'App' and principal_user_id IS NULL and principal_group_id IS NULL and principal_role_id IS NULL and principal_app_id IS NOT NULL)
      ),

      -- Verifies that there is only one scoped resource ID provided at most.
      CONSTRAINT scoped_resource_id_limit CHECK (
        (
          scoped_resource_type = 'Server'
          AND scoped_action_id IS NULL
          AND scoped_action_log_entry_id IS NULL
          AND scoped_app_id IS NULL
          AND scoped_app_authorization_id IS NULL
          AND scoped_app_authorization_credential_id IS NULL
          AND scoped_app_credential_id IS NULL
          AND scoped_configuration_id IS NULL
          AND scoped_delegation_policy_id IS NULL
          AND scoped_field_id IS NULL
          AND scoped_field_choice_id IS NULL
          AND scoped_field_value_id IS NULL
          AND scoped_group_id IS NULL
          AND scoped_http_transaction_id IS NULL
          AND scoped_item_id IS NULL
          AND scoped_item_connection_id IS NULL
          AND scoped_item_connection_type_id IS NULL
          AND scoped_membership_id IS NULL
          AND scoped_milestone_id IS NULL
          AND scoped_project_id IS NULL
          AND scoped_role_id IS NULL
          AND scoped_server_log_entry_id IS NULL
          AND scoped_session_id IS NULL
          AND scoped_user_id IS NULL
          AND scoped_view_id IS NULL
          AND scoped_workspace_id IS NULL
        ) OR (
          (scoped_action_id IS NOT NULL)::INTEGER +
          (scoped_action_log_entry_id IS NOT NULL)::INTEGER +
          (scoped_app_id IS NOT NULL)::INTEGER +
          (scoped_app_authorization_id IS NOT NULL)::INTEGER +
          (scoped_app_authorization_credential_id IS NOT NULL)::INTEGER +
          (scoped_app_credential_id IS NOT NULL)::INTEGER +
          (scoped_configuration_id IS NOT NULL)::INTEGER +
          (scoped_delegation_policy_id IS NOT NULL)::INTEGER +
          (scoped_field_id IS NOT NULL)::INTEGER +
          (scoped_field_choice_id IS NOT NULL)::INTEGER +
          (scoped_field_value_id IS NOT NULL)::INTEGER +
          (scoped_group_id IS NOT NULL)::INTEGER +
          (scoped_http_transaction_id IS NOT NULL)::INTEGER +
          (scoped_item_id IS NOT NULL)::INTEGER +
          (scoped_item_connection_id IS NOT NULL)::INTEGER +
          (scoped_item_connection_type_id IS NOT NULL)::INTEGER +
          (scoped_membership_id IS NOT NULL)::INTEGER +
          (scoped_milestone_id IS NOT NULL)::INTEGER +
          (scoped_project_id IS NOT NULL)::INTEGER +
          (scoped_role_id IS NOT NULL)::INTEGER +
          (scoped_server_log_entry_id IS NOT NULL)::INTEGER +
          (scoped_session_id IS NOT NULL)::INTEGER +
          (scoped_user_id IS NOT NULL)::INTEGER +
          (scoped_view_id IS NOT NULL)::INTEGER +
          (scoped_workspace_id IS NOT NULL)::INTEGER = 1
        )
      ),

      -- Verifies that the scoped resource ID matches the scoped resource type.
      CONSTRAINT scoped_resource_id_match CHECK (
        scoped_resource_type = 'Server'
        OR (scoped_resource_type = 'Action' AND scoped_action_id IS NOT NULL)
        OR (scoped_resource_type = 'ActionLogEntry' AND scoped_action_log_entry_id IS NOT NULL)
        OR (scoped_resource_type = 'App' AND scoped_app_id IS NOT NULL)
        OR (scoped_resource_type = 'AppAuthorization' AND scoped_app_authorization_id IS NOT NULL)
        OR (scoped_resource_type = 'AppAuthorizationCredential' AND scoped_app_authorization_credential_id IS NOT NULL)
        OR (scoped_resource_type = 'AppCredential' AND scoped_app_credential_id IS NOT NULL)
        OR (scoped_resource_type = 'Configuration' AND scoped_configuration_id IS NOT NULL)
        OR (scoped_resource_type = 'DelegationPolicy' AND scoped_delegation_policy_id IS NOT NULL)
        OR (scoped_resource_type = 'Field' AND scoped_field_id IS NOT NULL)
        OR (scoped_resource_type = 'FieldChoice' AND scoped_field_choice_id IS NOT NULL)
        OR (scoped_resource_type = 'FieldValue' AND scoped_field_value_id IS NOT NULL)
        OR (scoped_resource_type = 'Group' AND scoped_group_id IS NOT NULL)
        OR (scoped_resource_type = 'HTTPTransaction' AND scoped_http_transaction_id IS NOT NULL)
        OR (scoped_resource_type = 'Item' AND scoped_item_id IS NOT NULL)
        OR (scoped_resource_type = 'ItemConnection' AND scoped_item_connection_id IS NOT NULL)
        OR (scoped_resource_type = 'ItemConnectionType' AND scoped_item_connection_type_id IS NOT NULL)
        OR (scoped_resource_type = 'Membership' AND scoped_membership_id IS NOT NULL)
        OR (scoped_resource_type = 'Milestone' AND scoped_milestone_id IS NOT NULL)
        OR (scoped_resource_type = 'Project' AND scoped_project_id IS NOT NULL)
        OR (scoped_resource_type = 'Role' AND scoped_role_id IS NOT NULL)
        OR (scoped_resource_type = 'ServerLogEntry' AND scoped_server_log_entry_id IS NOT NULL)
        OR (scoped_resource_type = 'Session' AND scoped_session_id IS NOT NULL)
        OR (scoped_resource_type = 'User' AND scoped_user_id IS NOT NULL)
        OR (scoped_resource_type = 'View' AND scoped_view_id IS NOT NULL)
        OR (scoped_resource_type = 'Workspace' AND scoped_workspace_id IS NOT NULL)
      )
    );
  END
$$ LANGUAGE plpgsql;