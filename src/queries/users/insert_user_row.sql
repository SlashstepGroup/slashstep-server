INSERT INTO users (
  username, 
  display_name, 
  hashed_password, 
  is_anonymous, 
  ip_address
) VALUES (
  $1, 
  $2, 
  $3, 
  $4, 
  $5
) RETURNING *;