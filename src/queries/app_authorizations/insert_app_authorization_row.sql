insert into app_authorizations (
  app_id,
  authorizing_resource_type,
  authorizing_project_id,
  authorizing_workspace_id,
  authorizing_user_id
) values (
  $1,
  $2,
  $3,
  $4,
  $5
) returning *;