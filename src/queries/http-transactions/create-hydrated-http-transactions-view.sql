create or replace view hydrated_http_requests as
  select
    http_requests.*
  from 
    http_requests