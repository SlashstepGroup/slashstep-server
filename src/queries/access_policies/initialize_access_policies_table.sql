DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'permission_level') THEN
      CREATE TYPE permission_level AS ENUM (
        'None',
        'User',
        'Editor',
        'Admin'
      );
    END IF;

    if not exists (SELECT 1 FROM pg_type WHERE typname = 'resource_type') THEN
      CREATE TYPE resource_type AS ENUM (
        'AccessPolicy',
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'Group',
        'GroupMembership',
        'HTTPTransaction',
        'Server',
        'Item',
        'Milestone',
        'Project',
        'Role',
        'RoleMembership',
        'ServerLogEntry',
        'Session',
        'User',
        'Workspace'
      );
    END IF;

    if not exists (SELECT 1 FROM pg_type WHERE typname = 'access_policy_resource_type') THEN
      CREATE TYPE access_policy_resource_type AS ENUM (
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'Group',
        'GroupMembership',
        'HTTPTransaction',
        'Server',
        'Item',
        'Milestone',
        'Project',
        'Role',
        'RoleMembership',
        'ServerLogEntry',
        'Session',
        'User',
        'Workspace'
      );
    END IF;

    if not exists (SELECT 1 FROM pg_type WHERE typname = 'principal_type') THEN
      CREATE TYPE principal_type AS ENUM (
        'User',
        'Group',
        'Role',
        'App'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS access_policies (
      id UUID default uuidv7() primary key,

      /* Principals */
      principal_type principal_type not null,
      principal_user_id UUID references users(id) on delete cascade,
      principal_group_id UUID references groups(id) on delete cascade,
      principal_role_id UUID references roles(id) on delete cascade,
      principal_app_id UUID references apps(id) on delete cascade,

      /* Scopes */
      scoped_resource_type access_policy_resource_type not null,
      scoped_action_id UUID references actions(id) on delete cascade,
      scoped_action_log_entry_id UUID references action_log_entries(id) on delete cascade,
      scoped_app_id UUID references apps(id) on delete cascade,
      scoped_app_authorization_id UUID references app_authorizations(id) on delete cascade,
      scoped_app_authorization_credential_id UUID references app_authorization_credentials(id) on delete cascade,
      scoped_app_credential_id UUID references app_credentials(id) on delete cascade,
      scoped_group_id UUID references groups(id) on delete cascade,
      scoped_group_membership_id UUID references group_memberships(id) on delete cascade,
      scoped_http_transaction_id UUID references http_transactions(id) on delete cascade,
      scoped_item_id UUID references items(id) on delete cascade,
      scoped_milestone_id UUID references milestones(id) on delete cascade,
      scoped_project_id UUID references projects(id) on delete cascade,
      scoped_role_id UUID references roles(id) on delete cascade,
      scoped_role_membership_id UUID references role_memberships(id) on delete cascade,
      scoped_server_log_entry_id UUID references server_log_entries(id) on delete cascade,
      scoped_session_id UUID references sessions(id) on delete cascade,
      scoped_user_id UUID references users(id) on delete cascade,
      scoped_workspace_id UUID references workspaces(id) on delete cascade,

      /* Permissions */
      action_id UUID not null references actions(id) on delete cascade,
      permission_level permission_level not null,
      is_inheritance_enabled BOOLEAN not null,

      /* Constraints */
      constraint one_principal_type check (
        (principal_type = 'User' and principal_user_id is not null and principal_group_id is null and principal_role_id is null and principal_app_id is null)
        or (principal_type = 'Group' and principal_user_id is null and principal_group_id is not null and principal_role_id is null and principal_app_id is null)
        or (principal_type = 'Role' and principal_user_id is null and principal_group_id is null and principal_role_id is not null and principal_app_id is null)
        or (principal_type = 'App' and principal_user_id is null and principal_group_id is null and principal_role_id is null and principal_app_id is not null)
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
          AND scoped_group_id IS NULL
          AND scoped_group_membership_id IS NULL
          AND scoped_http_transaction_id IS NULL
          AND scoped_item_id IS NULL
          AND scoped_milestone_id IS NULL
          AND scoped_project_id IS NULL
          AND scoped_role_id IS NULL
          AND scoped_role_membership_id IS NULL
          AND scoped_server_log_entry_id IS NULL
          AND scoped_session_id IS NULL
          AND scoped_user_id IS NULL
          AND scoped_workspace_id IS NULL
        ) OR (
          (scoped_action_id IS NOT NULL)::INTEGER +
          (scoped_action_log_entry_id IS NOT NULL)::INTEGER +
          (scoped_app_id IS NOT NULL)::INTEGER +
          (scoped_app_authorization_id IS NOT NULL)::INTEGER +
          (scoped_app_authorization_credential_id IS NOT NULL)::INTEGER +
          (scoped_app_credential_id IS NOT NULL)::INTEGER +
          (scoped_group_id IS NOT NULL)::INTEGER +
          (scoped_group_membership_id IS NOT NULL)::INTEGER +
          (scoped_http_transaction_id IS NOT NULL)::INTEGER +
          (scoped_item_id IS NOT NULL)::INTEGER +
          (scoped_milestone_id IS NOT NULL)::INTEGER +
          (scoped_project_id IS NOT NULL)::INTEGER +
          (scoped_role_id IS NOT NULL)::INTEGER +
          (scoped_role_membership_id IS NOT NULL)::INTEGER +
          (scoped_server_log_entry_id IS NOT NULL)::INTEGER +
          (scoped_session_id IS NOT NULL)::INTEGER +
          (scoped_user_id IS NOT NULL)::INTEGER +
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
        OR (scoped_resource_type = 'Group' AND scoped_group_id IS NOT NULL)
        OR (scoped_resource_type = 'GroupMembership' AND scoped_group_membership_id IS NOT NULL)
        OR (scoped_resource_type = 'HTTPTransaction' AND scoped_http_transaction_id IS NOT NULL)
        OR (scoped_resource_type = 'Item' AND scoped_item_id IS NOT NULL)
        OR (scoped_resource_type = 'Milestone' AND scoped_milestone_id IS NOT NULL)
        OR (scoped_resource_type = 'Project' AND scoped_project_id IS NOT NULL)
        OR (scoped_resource_type = 'Role' AND scoped_role_id IS NOT NULL)
        OR (scoped_resource_type = 'RoleMembership' AND scoped_role_membership_id IS NOT NULL)
        OR (scoped_resource_type = 'ServerLogEntry' AND scoped_server_log_entry_id IS NOT NULL)
        OR (scoped_resource_type = 'Session' AND scoped_session_id IS NOT NULL)
        OR (scoped_resource_type = 'User' AND scoped_user_id IS NOT NULL)
        OR (scoped_resource_type = 'Workspace' AND scoped_workspace_id IS NOT NULL)
      )
    );
  END
$$ LANGUAGE plpgsql;