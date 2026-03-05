DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS item_types (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    item_type_icon_id UUID REFERENCES item_type_icons(id) ON DELETE SET NULL,
    description TEXT,
  );

END
$$ LANGUAGE plpgsql;
