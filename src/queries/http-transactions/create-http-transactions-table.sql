create table if not exists http_requests (
  id UUID default uuidv7() primary key,
  method text not null,
  url text not null,
  ip_address inet not null,
  headers text not null,
  status_code integer,
  expiration_date timestamptz not null default now() + interval '14 days'
);