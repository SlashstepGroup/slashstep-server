DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS fields (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    is_required BOOLEAN NOT NULL,
    type field_value_type NOT NULL, /* Defined in general types */
    minimum_value DECIMAL,
    maximum_value DECIMAL,
    minimum_choice_count INTEGER,
    maximum_choice_count INTEGER,
    parent_project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    is_deadline BOOLEAN,
    CONSTRAINT deadline_is_date CHECK (
      is_deadline IS NULL OR type = 'Timestamp'
    )
  );

  CREATE UNIQUE INDEX IF NOT EXISTS fields_name_unique ON fields (upper(name), parent_project_id);

END
$$ LANGUAGE plpgsql;
