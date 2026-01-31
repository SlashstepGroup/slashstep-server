insert into app_authorization_credentials (
  app_authorization_id,
  access_token_expiration_date,
  refresh_token_expiration_date,
  refreshed_app_authorization_credential_id
) values (
  $1,
  $2,
  $3,
  $4
) returning *;