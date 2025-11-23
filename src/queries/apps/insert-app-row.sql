insert into apps (
  name,
  display_name,
  description,
  parent_resource_type,
  parent_user_id,
  parent_workspace_id,
  client_type,
  client_secret_hash
) values (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8
) returning *;