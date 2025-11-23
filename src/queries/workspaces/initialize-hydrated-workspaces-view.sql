create or replace view hydrated_workspaces as
  select
    workspaces.*
  from 
    workspaces
  -- left join
  --   users as principal_users on principal_users.id = access_policies.principal_user_id
  