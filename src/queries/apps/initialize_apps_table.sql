do $$
begin
  if not exists (select 1 from pg_type where typname = 'app_parent_resource_type') then
    create type app_parent_resource_type as enum (
      'Server',
      'User',
      'Workspace'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'app_client_type') then
    create type app_client_type as enum (
      'Public',
      'Confidential'
    );
  end if;

  create table if not exists apps (
    id UUID default uuidv7() primary key,
    description text,
    name text not null,
    display_name text not null,
    parent_resource_type app_parent_resource_type not null,
    parent_user_id uuid,
    parent_workspace_id uuid,
    client_type app_client_type not null,
    client_secret_hash text
  );

end
$$ LANGUAGE plpgsql;