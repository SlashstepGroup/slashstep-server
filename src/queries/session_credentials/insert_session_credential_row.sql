INSERT INTO session_credentials (
  session_id, 
  user_id,
  creation_ip_address,
  access_token_expiration_date,
  refresh_token_expiration_date,
  refreshed_session_credential_id
) VALUES (
  $1, 
  $2, 
  $3,
  $4,
  $5,
  $6
) RETURNING *;