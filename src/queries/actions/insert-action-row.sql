insert into actions (
  name, 
  display_name, 
  description, 
  app_id
) values (
  $1, 
  $2, 
  $3, 
  $4
) returning *;