INSERT INTO memberships (
  parent_resource_type,
  parent_group_id,
  parent_role_id,
  principal_type, 
  principal_user_id, 
  principal_group_id, 
  principal_app_id
) VALUES (
  $1, 
  $2, 
  $3, 
  $4, 
  $5,
  $6,
  $7
) RETURNING *;