INSERT INTO app_authorizations (
  app_id,
  authorizing_resource_type,
  authorizing_project_id,
  authorizing_workspace_id,
  authorizing_user_id,
  oauth_authorization_id
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;