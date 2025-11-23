create or replace view hydrated_access_policies as
  select
    access_policies.*,
    row_to_json(actions.*) as action,

    row_to_json(principal_users.*) as principal_user,
    row_to_json(principal_groups.*) as principal_group,
    row_to_json(principal_roles.*) as principal_role,
    row_to_json(principal_apps.*) as principal_app,

    row_to_json(scoped_actions.*) as scoped_action,
    row_to_json(scoped_apps.*) as scoped_app,
    row_to_json(scoped_groups.*) as scoped_group,
    row_to_json(scoped_items.*) as scoped_item,
    row_to_json(scoped_milestones.*) as scoped_milestone,
    row_to_json(scoped_projects.*) as scoped_project,
    row_to_json(scoped_roles.*) as scoped_role,
    row_to_json(scoped_users.*) as scoped_user,
    row_to_json(scoped_workspaces.*) as scoped_workspace,
    row_to_json(scoped_app_authorizations.*) as scoped_app_authorization,
    row_to_json(scoped_app_authorization_credentials.*) as scoped_app_authorization_credential,
    row_to_json(scoped_app_credentials.*) as scoped_app_credential
  from 
    access_policies
  left join
    users as principal_users on principal_users.id = access_policies.principal_user_id
  left join
    groups as principal_groups on principal_groups.id = access_policies.principal_group_id
  left join
    roles as principal_roles on principal_roles.id = access_policies.principal_role_id
  left join
    apps as principal_apps on principal_apps.id = access_policies.principal_app_id
  left join 
    actions as actions on actions.id = access_policies.action_id
  left join
    actions as scoped_actions on scoped_actions.id = access_policies.scoped_action_id
  left join
    apps as scoped_apps on scoped_apps.id = access_policies.scoped_app_id
  left join
    groups as scoped_groups on scoped_groups.id = access_policies.scoped_group_id
  left join 
    items as scoped_items on scoped_items.id = access_policies.scoped_item_id
  left join 
    milestones as scoped_milestones on scoped_milestones.id = access_policies.scoped_milestone_id
  left join 
    projects as scoped_projects on scoped_projects.id = access_policies.scoped_project_id
  left join
    roles as scoped_roles on scoped_roles.id = access_policies.scoped_role_id
  left join 
    users as scoped_users on scoped_users.id = access_policies.scoped_user_id
  left join 
    workspaces as scoped_workspaces on scoped_workspaces.id = access_policies.scoped_workspace_id
  left join
    app_authorizations as scoped_app_authorizations on scoped_app_authorizations.id = access_policies.scoped_app_authorization_id
  left join
    app_authorization_credentials as scoped_app_authorization_credentials on scoped_app_authorization_credentials.id = access_policies.scoped_app_authorization_credential_id
  left join
    app_credentials as scoped_app_credentials on scoped_app_credentials.id = access_policies.scoped_app_credential_id