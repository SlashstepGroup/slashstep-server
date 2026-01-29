create or replace view hydrated_actions as
  select
    actions.*,
    row_to_json(apps.*) as app
  from
    actions
  left join
    apps on apps.id = actions.parent_app_id;