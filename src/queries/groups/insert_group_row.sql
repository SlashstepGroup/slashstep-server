INSERT INTO groups (
  name,
  display_name,
  description,
  parent_resource_type,
  parent_group_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
) RETURNING *;