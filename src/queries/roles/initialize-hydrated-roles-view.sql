create or replace view hydrated_roles as
  select
    roles.*
  from 
    roles
  -- left join
  --   users as principal_users on principal_users.id = access_policies.principal_user_id
  