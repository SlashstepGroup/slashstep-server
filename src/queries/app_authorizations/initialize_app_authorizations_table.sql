do $$
begin

  if not exists (select 1 from pg_type where typname = 'app_authorization_authorizing_resource_type') then
    create type app_authorization_authorizing_resource_type as enum (
      'Instance',
      'Workspace',
      'Project',
      'User'
    );
  end if;

  create table if not exists app_authorizations (
    id UUID default uuidv7() primary key,
    app_id UUID references apps(id) on delete cascade,
    authorizing_resource_type app_authorization_authorizing_resource_type not null,
    authorizing_project_id UUID references projects(id) on delete cascade,
    authorizing_user_id UUID references users(id) on delete cascade,
    authorizing_workspace_id UUID references workspaces(id) on delete cascade
  );
  
end
$$ LANGUAGE plpgsql;