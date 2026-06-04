CREATE TABLE IF NOT EXISTS session_credentials (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creation_ip_address INET NOT NULL,
  access_token_expiration_date TIMESTAMPTZ NOT NULL,
  refresh_token_expiration_date TIMESTAMPTZ NOT NULL,
  refreshed_session_credential_id UUID
);