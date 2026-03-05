INSERT INTO iterations (
  parent_project_id,
  display_name,
  start_date,
  end_date,
  actual_start_date,
  actual_end_date
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;