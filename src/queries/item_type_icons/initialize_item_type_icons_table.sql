DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS item_type_icons (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    /* TODO: Support S3 or other external storage for icons in the future */
    local_file_path TEXT NOT NULL
  );

END
$$ LANGUAGE plpgsql;
