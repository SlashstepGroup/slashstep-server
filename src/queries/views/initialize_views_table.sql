DO $$
  BEGIN

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'view_type') THEN
      CREATE TYPE view_type AS ENUM (
        'Table',
        'Kanban',
        'List',
        'Timeline'
      );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'view_parent_resource_type') THEN
      CREATE TYPE view_parent_resource_type AS ENUM (
        'Workspace',
        'Project'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS views (
      id UUID DEFAULT uuidv7() PRIMARY KEY,
      name TEXT NOT NULL,
      display_name TEXT NOT NULL,
      default_query TEXT,
      type view_type NOT NULL,
      parent_resource_type view_parent_resource_type,
      parent_workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
      parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE
    );

  END
$$ LANGUAGE plpgsql;
