insert into actions (
  name, 
  display_name, 
  description, 
  app_id,
  parent_resource_type
) values (
  $1, 
  $2, 
  $3, 
  $4,
  $5
) returning *;