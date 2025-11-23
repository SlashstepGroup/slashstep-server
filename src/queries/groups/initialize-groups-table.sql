create table if not exists groups (
  id UUID default uuidv7() primary key,
  name text not null unique,
  display_name text not null,
  description text not null,
  parent_group_id UUID references groups(id) on delete cascade
)