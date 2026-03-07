DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS projects (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    key TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    parent_workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE
  );

  CREATE UNIQUE INDEX IF NOT EXISTS projects_name_unique ON projects (upper(name), parent_workspace_id);
  CREATE UNIQUE INDEX IF NOT EXISTS projects_key_unique ON projects (upper(key), parent_workspace_id);

END
$$ LANGUAGE plpgsql;