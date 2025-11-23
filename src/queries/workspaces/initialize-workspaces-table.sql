do $$
begin

  create table if not exists workspaces (
    id UUID default uuidv7() primary key,
    name text not null,
    display_name text not null,
    description text
  );

  create unique index if not exists workspaces_name_unique on workspaces (upper(name));

end
$$ language plpgsql;