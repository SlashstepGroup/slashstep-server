DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'item_type_icon_parent_resource_type') THEN
    CREATE TYPE item_type_icon_parent_resource_type AS ENUM (
      'Server',
      'Project'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS item_type_icons (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    display_name TEXT NOT NULL,
    parent_resource_type item_type_icon_parent_resource_type NOT NULL,
    parent_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    /* TODO: Support S3 or other external storage for icons in the future */
    local_file_path TEXT NOT NULL,
    CONSTRAINT item_type_icon_parent_resource_type_check CHECK (
      (parent_resource_type = 'Server' AND parent_project_id IS NULL) OR
      (parent_resource_type = 'Project' AND parent_project_id IS NOT NULL)
    )
  );

END
$$ LANGUAGE plpgsql;
