create table if not exists app_credentials (
  id UUID default uuidv7() primary key,
  app_id UUID not null references apps(id) on delete cascade,
  description TEXT,
  expiration_date TIMESTAMPTZ not null,
  creation_ip_address INET not null,
  public_key TEXT not null
);