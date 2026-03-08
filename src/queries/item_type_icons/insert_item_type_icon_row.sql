INSERT INTO item_type_icons (
  display_name,
  parent_resource_type,
  parent_project_id,
  local_file_path
) VALUES (
  $1,
  $2,
  $3,
  $4
) RETURNING *;