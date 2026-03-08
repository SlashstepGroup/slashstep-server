INSERT INTO statuses (
  display_name,
  status_type,
  decimal_color,
  description,
  next_status_id,
  parent_project_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;