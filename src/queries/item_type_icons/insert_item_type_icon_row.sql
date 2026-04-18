INSERT INTO item_type_icons (
  id,
  display_name,
  parent_resource_type,
  parent_project_id
) VALUES (
  COALESCE($1, uuidv7()),
  $2,
  $3,
  $4
) RETURNING *;