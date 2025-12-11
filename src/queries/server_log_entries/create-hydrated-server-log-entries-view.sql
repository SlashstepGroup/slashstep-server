create or replace view hydrated_server_log_entries as
  select
    server_log_entries.*
  from 
    server_log_entries