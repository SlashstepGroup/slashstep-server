DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'item_connection_type_parent_resource_type') THEN
    CREATE TYPE item_connection_type_parent_resource_type AS ENUM (
      'Project',
      'Workspace'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS item_connection_types (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    display_name TEXT NOT NULL,
    inward_description TEXT NOT NULL,
    outward_description TEXT NOT NULL,
    parent_resource_type item_connection_type_parent_resource_type NOT NULL,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE
  );

END
$$ LANGUAGE plpgsql;