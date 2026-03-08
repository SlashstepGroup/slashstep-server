INSERT INTO view_fields (
  parent_view_id,
  field_id,
  next_view_field_id
) VALUES (
  $1,
  $2,
  $3
) RETURNING *;