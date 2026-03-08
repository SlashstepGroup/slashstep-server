DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS iterations (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    parent_project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    actual_start_date TIMESTAMPTZ,
    actual_end_date TIMESTAMPTZ
  );

END
$$ LANGUAGE plpgsql;
