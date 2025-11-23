create or replace view hydrated_app_authorization_credentials as
  select
    app_authorization_credentials.*
  from 
    app_authorization_credentials
  -- left join
  --   users as principal_users on principal_users.id = access_policies.principal_user_id
  