DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'milestone_parent_type') THEN
    CREATE TYPE milestone_parent_type AS ENUM (
      'Workspace',
      'Project'
    );
  END IF;

  create table if not exists milestones (
    id UUID default uuidv7() primary key,
    name text not null unique,
    display_name text not null,
    description text not null,
    parent_resource_type milestone_parent_type not null,
    parent_project_id UUID references projects(id) on delete cascade,
    parent_workspace_id UUID references workspaces(id) on delete cascade
  );

  CREATE UNIQUE INDEX IF NOT EXISTS unique_milestone_name ON milestones(UPPER(name), parent_project_id, parent_workspace_id, parent_resource_type);

END
$$ LANGUAGE plpgsql;