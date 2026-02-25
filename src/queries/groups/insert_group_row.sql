INSERT INTO groups (
  name,
  display_name,
  description
) VALUES (
  $1,
  $2,
  $3
) RETURNING *;