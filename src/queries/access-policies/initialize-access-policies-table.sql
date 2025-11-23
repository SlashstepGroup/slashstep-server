do $$
begin
  if not exists (select 1 from pg_type where typname = 'permission_level') then
    create type permission_level as enum (
      'None',
      'User',
      'Editor',
      'Admin'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'inheritance_level') then
    create type inheritance_level as enum (
      'Disabled',
      'Enabled',
      'Required'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'scoped_resource_type') then
    create type scoped_resource_type as enum (
      'Instance',
      'Workspace',
      'Project',
      'Item',
      'Action',
      'User',
      'Role',
      'Group',
      'App',
      'AppCredential',
      'Milestone'
    );
  end if;

  if not exists (select 1 from pg_type where typname = 'principal_type') then
    create type principal_type as enum (
      'User',
      'Group',
      'Role',
      'App'
    );
  end if;

  create table if not exists access_policies (
    id UUID default uuidv7() primary key,

    /* Principals */
    principal_type principal_type not null,
    principal_user_id UUID references users(id) on delete cascade,
    principal_group_id UUID references groups(id) on delete cascade,
    principal_role_id UUID references roles(id) on delete cascade,
    principal_app_id UUID references apps(id) on delete cascade,

    /* Scopes */
    scoped_resource_type scoped_resource_type not null,
    scoped_workspace_id UUID references workspaces(id) on delete cascade,
    scoped_project_id UUID references projects(id) on delete cascade,
    scoped_item_id UUID references items(id) on delete cascade,
    scoped_action_id UUID references actions(id) on delete cascade,
    scoped_user_id UUID references users(id) on delete cascade,
    scoped_role_id UUID references roles(id) on delete cascade,
    scoped_group_id UUID references groups(id) on delete cascade,
    scoped_app_id UUID references apps(id) on delete cascade,
    scoped_app_credential_id UUID references app_credentials(id) on delete cascade,
    scoped_app_authorization_id UUID references app_authorizations(id) on delete cascade,
    scoped_app_authorization_credential_id UUID references app_authorization_credentials(id) on delete cascade,
    scoped_milestone_id UUID references milestones(id) on delete cascade,

    /* Permissions */
    action_id UUID not null references actions(id) on delete cascade,
    permission_level permission_level not null,
    inheritance_level inheritance_level not null,
    
    /* Constraints */
    constraint one_principal_type check (
      (principal_type = 'User' and principal_user_id is not null and principal_group_id is null and principal_role_id is null and principal_app_id is null)
      or (principal_type = 'Group' and principal_user_id is null and principal_group_id is not null and principal_role_id is null and principal_app_id is null)
      or (principal_type = 'Role' and principal_user_id is null and principal_group_id is null and principal_role_id is not null and principal_app_id is null)
      or (principal_type = 'App' and principal_user_id is null and principal_group_id is null and principal_role_id is null and principal_app_id is not null)
    ),

    constraint one_scoped_resource_type check (
      (scoped_resource_type = 'Instance' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Workspace' and scoped_workspace_id is not null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Project' and scoped_workspace_id is null and scoped_project_id is not null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Item' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is not null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Action' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is not null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'User' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is not null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Role' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is not null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Group' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is not null and scoped_app_id is null and scoped_milestone_id is null)
      or (scoped_resource_type = 'App' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is not null and scoped_milestone_id is null)
      or (scoped_resource_type = 'Milestone' and scoped_workspace_id is null and scoped_project_id is null and scoped_item_id is null and scoped_action_id is null and scoped_user_id is null and scoped_role_id is null and scoped_group_id is null and scoped_app_id is null and scoped_milestone_id is not null)
    )
  );
end
$$ LANGUAGE plpgsql;