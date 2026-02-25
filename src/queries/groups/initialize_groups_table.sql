DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_parent_resource_type') THEN
    CREATE TYPE group_parent_resource_type AS ENUM (
      'Server',
      'Group'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS groups (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT
  );

END
$$ LANGUAGE plpgsql;