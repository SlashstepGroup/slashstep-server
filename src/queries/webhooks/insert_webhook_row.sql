INSERT INTO webhooks (
  display_name,
  url,
  hashed_secret,
  is_enabled,
  parent_resource_type,
  parent_app_id,
  parent_group_id,
  parent_project_id,
  parent_user_id,
  parent_workspace_id
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