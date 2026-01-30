insert into apps (
  name,
  display_name,
  description,
  client_type,
  client_secret_hash,
  parent_resource_type,
  parent_workspace_id,
  parent_user_id
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