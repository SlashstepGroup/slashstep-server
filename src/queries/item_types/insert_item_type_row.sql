INSERT INTO item_types (
  name,
  display_name,
  item_type_icon_id,
  parent_project_id,
  description
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
) RETURNING *;