DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'field_type') THEN
    CREATE TYPE field_type AS ENUM (
      'Text',
      'Number',
      'Boolean',
      'DateTime',
      'Stakeholder'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'field_parent_resource_type') THEN
    CREATE TYPE field_parent_resource_type AS ENUM (
      'Project',
      'Workspace',
      'User'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS fields (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    is_required BOOLEAN NOT NULL,
    type field_type NOT NULL,
    minimum_value NUMERIC,
    maximum_value NUMERIC,
    minimum_choice_count INTEGER,
    maximum_choice_count INTEGER,
    parent_resource_type field_parent_resource_type NOT NULL,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    parent_user_id UUID REFERENCES users(id) ON DELETE CASCADE
  );

END
$$ LANGUAGE plpgsql;
