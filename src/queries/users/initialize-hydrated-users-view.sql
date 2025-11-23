create or replace view hydrated_users as
  select
    users.*
  from 
    users
  -- left join
  --   users as principal_users on principal_users.id = access_policies.principal_user_id
  