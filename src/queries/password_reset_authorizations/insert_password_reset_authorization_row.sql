INSERT INTO password_reset_authorizations (
  user_id, 
  expiration_date
) VALUES (
  $1,
  $2
) RETURNING *;