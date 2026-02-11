DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'field_parent_resource_type') THEN
    CREATE TYPE field_parent_resource_type AS ENUM (
      'Project',
      'Workspace'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS fields (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    is_required BOOLEAN NOT NULL,
    type field_value_type NOT NULL,
    minimum_value DECIMAL,
    maximum_value DECIMAL,
    minimum_choice_count INTEGER,
    maximum_choice_count INTEGER,
    parent_resource_type field_parent_resource_type NOT NULL,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    is_deadline BOOLEAN,
    CONSTRAINT one_parent_type CHECK (
      (parent_resource_type = 'Project' AND parent_project_id IS NOT NULL AND parent_workspace_id IS NULL)
      OR (parent_resource_type = 'Workspace' AND parent_project_id IS NULL AND parent_workspace_id IS NOT NULL)
    ),
    CONSTRAINT deadline_is_date CHECK (
      is_deadline IS NULL OR type = 'Timestamp'
    )
  );

  CREATE UNIQUE INDEX IF NOT EXISTS fields_name_unique ON fields (upper(name));

END
$$ LANGUAGE plpgsql;
