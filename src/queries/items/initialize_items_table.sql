create table if not exists items (
  id UUID default uuidv7() primary key,
  summary text not null,
  description text,
  project_id UUID not null references projects(id) on delete cascade,
  number bigint not null,
  unique (number, project_id)
);