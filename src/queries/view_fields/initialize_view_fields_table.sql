DO $$
  BEGIN

    CREATE TABLE IF NOT EXISTS view_fields (
      id UUID DEFAULT uuidv7() PRIMARY KEY,
      parent_view_id UUID NOT NULL REFERENCES views(id) ON DELETE CASCADE,
      field_id UUID NOT NULL REFERENCES fields(id) ON DELETE CASCADE,
      next_view_field_id UUID REFERENCES view_fields(id),
      UNIQUE (parent_view_id, field_id)
    );

  END
$$ LANGUAGE plpgsql;
