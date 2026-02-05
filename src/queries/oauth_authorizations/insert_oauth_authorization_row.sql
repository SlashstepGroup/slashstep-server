INSERT INTO oauth_authorizations (
  app_id,
  authorizing_user_id,
  code_challenge
) VALUES (
  $1,
  $2,
  $3
) RETURNING *;