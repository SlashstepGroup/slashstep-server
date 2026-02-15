insert into server_log_entries (
  message,
  http_transaction_id,
  level
) values (
  $1,
  $2,
  $3
) returning *;