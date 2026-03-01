INSERT INTO membership_invitations (
  parent_resource_type,
  parent_group_id,
  parent_role_id,
  invitee_principal_type, 
  invitee_principal_user_id, 
  invitee_principal_group_id, 
  invitee_principal_app_id,
  inviter_principal_type,
  inviter_principal_user_id,
  inviter_principal_app_id
) VALUES (
  $1, 
  $2, 
  $3, 
  $4, 
  $5,
  $6,
  $7,
  $8,
  $9,
  $10
) RETURNING *;