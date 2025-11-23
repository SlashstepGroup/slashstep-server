insert into access_policies (
  principal_type, principal_user_id, scope_type, action_id,
  permission_level, inheritance_level
) values (
  'User', $1, 'Instance', $2, 'Admin', 'Required'
);