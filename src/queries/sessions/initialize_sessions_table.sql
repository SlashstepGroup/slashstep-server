CREATE TABLE IF NOT EXISTS sessions (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  expiration_date timestamptz NOT NULL,
  creation_ip_address INET NOT NULL
);