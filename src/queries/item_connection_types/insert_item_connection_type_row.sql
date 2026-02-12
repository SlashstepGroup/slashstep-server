INSERT INTO item_connection_types (
  display_name,
  inward_description,
  outward_description,
  parent_resource_type,
  parent_project_id,
  parent_workspace_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;