INSERT INTO statuses (
  name,
  display_name,
  type,
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
  $6,
  $7
) RETURNING *;