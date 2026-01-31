create table if not exists app_authorization_credentials (
  id UUID default uuidv7() primary key,
  app_authorization_id UUID not null,
  access_token_expiration_date timestamptz not null,
  refresh_token_expiration_date timestamptz not null,
  refreshed_app_authorization_credential_id UUID
);