INSERT INTO sessions (
  user_id, 
  expiration_date, 
  creation_ip_address
) VALUES (
  $1, 
  $2, 
  $3
) RETURNING *;