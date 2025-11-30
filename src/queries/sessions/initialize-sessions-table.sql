create table if not exists sessions (
  id UUID default uuidv7() primary key,
  user_id UUID references users(id) on delete cascade,
  expiration_date timestamptz not null,
  creation_ip_address inet not null
);