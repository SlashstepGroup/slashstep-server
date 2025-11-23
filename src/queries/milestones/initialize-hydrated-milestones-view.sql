create or replace view hydrated_milestones as
  select
    milestones.*
  from 
    milestones
  -- left join
  --   users as principal_users on principal_users.id = access_policies.principal_user_id
  