DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_parent_resource_type') THEN
    CREATE TYPE group_parent_resource_type AS ENUM (
      'Server',
      'Group'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'protected_group_type') THEN
    CREATE TYPE protected_group_type AS ENUM (
      'AnonymousUsers',
      'RegisteredUsers'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS groups (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    parent_resource_type group_parent_resource_type NOT NULL,
    parent_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    protected_group_type protected_group_type
  );

END
$$ LANGUAGE plpgsql;