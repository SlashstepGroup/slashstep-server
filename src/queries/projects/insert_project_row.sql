insert into projects (
  name, 
  display_name, 
  key, 
  description, 
  start_date, 
  end_date, 
  workspace_id
) values (
  $1, 
  $2, 
  $3, 
  $4, 
  $5, 
  $6, 
  $7
) returning *;