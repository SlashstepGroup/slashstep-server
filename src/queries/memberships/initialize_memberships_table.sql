do $$
begin

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'membership_parent_resource_type') THEN
    CREATE TYPE membership_parent_resource_type AS ENUM (
      'Role',
      'Group'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'membership_principal_type') THEN
    CREATE TYPE membership_principal_type AS ENUM (
      'User',
      'Group',
      'App'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS memberships (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    parent_resource_type membership_parent_resource_type NOT NULL,
    parent_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    parent_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    principal_type membership_principal_type NOT NULL,
    principal_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    principal_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    principal_app_id UUID REFERENCES apps(id) ON DELETE CASCADE
  );

END
$$ LANGUAGE plpgsql;