INSERT INTO http_transactions (
  method,
  url,
  ip_address,
  headers,
  status_code,
  expiration_timestamp
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;