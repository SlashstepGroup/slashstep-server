DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'webhook_parent_resource_type') THEN
    CREATE TYPE webhook_parent_resource_type AS ENUM (
      'App',
      'Group',
      'Project',
      'Server',
      'User',
      'Workspace'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS webhooks (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    display_name TEXT NOT NULL,
    url TEXT NOT NULL,
    hashed_secret TEXT,
    is_enabled BOOLEAN NOT NULL,
    parent_resource_type webhook_parent_resource_type NOT NULL,
    parent_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    parent_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    parent_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT webhook_has_correct_parent_resource_id check (
      (
        parent_resource_type = 'App' AND 
        parent_app_id IS NOT NULL AND
        parent_group_id IS NULL AND
        parent_project_id IS NULL AND
        parent_user_id IS NULL AND
        parent_workspace_id IS NULL
      ) OR (
        parent_resource_type = 'Group' AND 
        parent_group_id IS NOT NULL AND
        parent_app_id IS NULL AND
        parent_project_id IS NULL AND
        parent_user_id IS NULL AND
        parent_workspace_id IS NULL
      ) OR (
        parent_resource_type = 'Project' AND 
        parent_project_id IS NOT NULL AND
        parent_app_id IS NULL AND
        parent_group_id IS NULL AND
        parent_user_id IS NULL AND
        parent_workspace_id IS NULL
      ) OR (
        parent_resource_type = 'Server' AND 
        parent_app_id IS NULL AND
        parent_group_id IS NULL AND
        parent_project_id IS NULL AND
        parent_user_id IS NULL AND
        parent_workspace_id IS NULL
      ) OR (
        parent_resource_type = 'User' AND 
        parent_user_id IS NOT NULL AND
        parent_app_id IS NULL AND
        parent_project_id IS NULL AND
        parent_group_id IS NULL AND
        parent_workspace_id IS NULL
      ) OR (
        parent_resource_type = 'Workspace' AND 
        parent_workspace_id IS NOT NULL AND
        parent_app_id IS NULL AND
        parent_project_id IS NULL AND
        parent_user_id IS NULL AND
        parent_group_id IS NULL
      )
    )
  );

END
$$ LANGUAGE plpgsql;
