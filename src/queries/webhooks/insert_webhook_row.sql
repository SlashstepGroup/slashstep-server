INSERT INTO statuses (
  name,
  display_name,
  status_type,
  decimal_color,
  description,
  parent_resource_type,
  parent_project_id,
  parent_workspace_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8
) RETURNING *;