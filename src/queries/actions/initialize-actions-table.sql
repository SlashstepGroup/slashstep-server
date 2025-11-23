create table if not exists actions (
  id UUID default uuidv7() primary key,
  name text not null unique,
  display_name text not null,
  description text not null,
  app_id UUID references apps(id) on delete cascade
);