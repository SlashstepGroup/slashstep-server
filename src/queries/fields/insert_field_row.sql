INSERT INTO fields (
  name,
  description,
  display_name,
  is_required,
  type,
  minimum_value,
  maximum_value,
  minimum_choice_count,
  maximum_choice_count,
  parent_resource_type,
  parent_project_id,
  parent_workspace_id,
  parent_user_id
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
  $10,
  $11,
  $12,
  $13
) RETURNING *;