DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_authorization_authorizing_resource_type') THEN
    CREATE TYPE app_authorization_authorizing_resource_type AS ENUM (
      'Server',
      'Workspace',
      'Project',
      'User'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS app_authorizations (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    authorizing_resource_type app_authorization_authorizing_resource_type NOT NULL,
    authorizing_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    authorizing_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    authorizing_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    oauth_authorization_id UUID REFERENCES oauth_authorizations(id) ON DELETE CASCADE
  );
  
END
$$ LANGUAGE plpgsql;