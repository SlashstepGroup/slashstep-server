DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'status_type') THEN
    CREATE TYPE status_type AS ENUM (
      'ToDo',
      'InProgress',
      'Done'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS statuses (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status_type status_type NOT NULL,
    decimal_color INTEGER,
    description TEXT,
    parent_project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE
  );

END
$$ LANGUAGE plpgsql;
