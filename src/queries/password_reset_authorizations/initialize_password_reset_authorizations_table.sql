CREATE TABLE IF NOT EXISTS password_reset_authorizations (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expiration_date TIMESTAMPTZ NOT NULL
);