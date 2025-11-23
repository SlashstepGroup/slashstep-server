insert into users (
  username, 
  display_name, 
  hashed_password, 
  is_anonymous, 
  ip_address
) values (
  $1, 
  $2, 
  $3, 
  $4, 
  $5
) returning *;