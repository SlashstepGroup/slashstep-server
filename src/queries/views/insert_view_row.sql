INSERT INTO views (
  name,
  display_name,
  default_query,
  type,
  parent_resource_type,
  parent_workspace_id,
  parent_project_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7
) RETURNING *;