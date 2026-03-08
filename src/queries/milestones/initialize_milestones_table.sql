DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'milestone_parent_resource_type') THEN
    CREATE TYPE milestone_parent_resource_type AS ENUM (
      'Workspace',
      'Project'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS milestones (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    parent_resource_type milestone_parent_resource_type NOT NULL,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE
  );

  CREATE UNIQUE INDEX IF NOT EXISTS unique_milestone_name ON milestones(UPPER(name), parent_project_id, parent_workspace_id, parent_resource_type);

END
$$ LANGUAGE plpgsql;