create or replace view hydrated_projects as 
  select
    projects.id,
    projects.name,
    projects.display_name,
    projects.description,
    projects.start_date,
    projects.end_date,
    projects.workspace_id,
    workspaces.name as workspace_name,
    workspaces.display_name as workspace_display_name,
    workspaces.description as workspace_description,
    projects.key
  from 
    projects
  inner join 
    workspaces on projects.workspace_id = workspaces.id