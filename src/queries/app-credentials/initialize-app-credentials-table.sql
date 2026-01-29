CREATE TABLE IF NOT EXISTS app_credentials (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  description TEXT,
  expiration_date TIMESTAMPTZ NOT NULL,
  creation_ip_address INET NOT NULL,
  public_key TEXT NOT NULL UNIQUE
);