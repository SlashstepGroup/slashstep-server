INSERT INTO app_credentials (
  app_id,
  description,
  expiration_date,
  creation_ip_address,
  public_key
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
) RETURNING *;