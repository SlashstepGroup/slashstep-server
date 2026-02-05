INSERT INTO delegation_policies (
  action_id,
  maximum_permission_level,
  delegate_app_authorization_id,
  principal_user_id
) VALUES (
  $1,
  $2,
  $3,
  $4
) RETURNING *;