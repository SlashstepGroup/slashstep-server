create or replace view hydrated_app_authorizations as
  select
    app_authorizations.*,
    row_to_json(apps.*) as app,
    row_to_json(users.*) as authorizing_user,
    row_to_json(workspaces.*) as authorizing_workspace,
    row_to_json(projects.*) as authorizing_project
  from 
    app_authorizations
  left join
    apps on app_authorizations.app_id = apps.id
  left join
    users on app_authorizations.authorizing_user_id = users.id
  left join
    workspaces on app_authorizations.authorizing_workspace_id = workspaces.id
  left join
    projects on app_authorizations.authorizing_project_id = projects.id