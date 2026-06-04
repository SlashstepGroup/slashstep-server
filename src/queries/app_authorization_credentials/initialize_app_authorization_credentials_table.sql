create table if not exists app_authorization_credentials (
  id UUID default uuidv7() primary key,
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  app_authorization_id UUID NOT NULL REFERENCES app_authorizations(id) ON DELETE CASCADE,
  access_token_expiration_date TIMESTAMPTZ NOT NULL,
  refresh_token_expiration_date TIMESTAMPTZ NOT NULL,
  refreshed_app_authorization_credential_id UUID
);