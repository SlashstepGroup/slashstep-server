INSERT INTO oauth_authorizations (
  app_id,
  authorizing_user_id,
  code_challenge,
  code_challenge_method,
  redirect_uri,
  scope,
  usage_date,
  state
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8
) RETURNING *;