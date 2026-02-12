INSERT INTO item_connections (
  item_connection_type_id,
  inward_item_id,
  outward_item_id
) VALUES (
  $1,
  $2,
  $3
) RETURNING *;