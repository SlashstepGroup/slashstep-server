INSERT INTO roles (
  name,
  display_name,
  description,
  parent_resource_type,
  parent_group_id,
  parent_workspace_id,
  parent_project_id,
  protected_role_type
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