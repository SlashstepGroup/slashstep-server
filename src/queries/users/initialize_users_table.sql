CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  username TEXT UNIQUE,
  display_name TEXT,
  ip_address INET UNIQUE,
  hashed_password TEXT,
  is_anonymous BOOLEAN NOT NULL,
  constraint required_fields check (
    (is_anonymous = true AND username IS NULL AND display_name IS NULL AND hashed_password IS NULL AND ip_address IS NOT NULL)
    OR (is_anonymous = false AND username IS NOT NULL AND display_name IS NOT NULL AND hashed_password IS NOT NULL AND ip_address IS NULL)
  )
)