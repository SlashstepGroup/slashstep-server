INSERT INTO
  password_reset_authorizations
VALUES 
  (
    $1,
    $2, 
    $3
  ) 
RETURNING *;