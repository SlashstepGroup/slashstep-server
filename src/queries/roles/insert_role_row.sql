INSERT INTO roles (
  name,
  display_name,
  description,
  parent_resource_type,
  parent_app_id,
  parent_group_id,
  parent_workspace_id,
  parent_project_id,
  parent_user_id,
  predefined_role_type
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $10
) RETURNING *;