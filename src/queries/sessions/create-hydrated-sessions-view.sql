create or replace view hydrated_sessions as
  select
    sessions.*,
    users.username as user_username,
    users.display_name as user_display_name
  from
    sessions
  inner join
    users on users.id = sessions.user_id;