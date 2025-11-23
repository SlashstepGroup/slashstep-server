create or replace view hydrated_items as 
  select 
    items.*,
    projects.name as project_name,
    projects.display_name as project_display_name,
    projects.key as project_key,
    projects.description as project_description,
    projects.start_date as project_start_date,
    projects.end_date as project_end_date,
    projects.workspace_id,
    workspaces.name as workspace_name,
    workspaces.display_name as workspace_display_name,
    workspaces.description as workspace_description
  from 
    items
  inner join 
    projects on items.project_id = projects.id
  inner join
    workspaces on projects.workspace_id = workspaces.id