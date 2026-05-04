CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  username TEXT UNIQUE,
  display_name TEXT,
  ip_address INET UNIQUE,
  hashed_password TEXT,
  is_anonymous BOOLEAN NOT NULL,
  CONSTRAINT username_existence_check CHECK (
    (is_anonymous = true AND username IS NULL) 
    OR (is_anonymous = false AND username IS NOT NULL)
  ),
  CONSTRAINT hashed_password_existence_check CHECK (
    (is_anonymous = true AND hashed_password IS NULL) 
    OR (is_anonymous = false AND hashed_password IS NOT NULL)
  ),
  CONSTRAINT ip_address_existence_check CHECK (
    (is_anonymous = true AND ip_address IS NOT NULL) 
    OR (is_anonymous = false AND ip_address IS NULL)
  )
)