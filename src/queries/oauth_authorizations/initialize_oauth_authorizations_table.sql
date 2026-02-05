CREATE TABLE IF NOT EXISTS oauth_authorizations (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  authorizing_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  code_challenge TEXT
);