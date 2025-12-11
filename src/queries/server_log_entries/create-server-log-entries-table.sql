do $$
begin
  if not exists (select 1 from pg_type where typname = 'server_log_entry_level') then
    create type server_log_entry_level as enum (
      'Success',
      'Trace',
      'Info',
      'Warning',
      'Error',
      'Critical'
    );
  end if;
end
$$ LANGUAGE plpgsql;

create table if not exists server_log_entries (
  id UUID default uuidv7() primary key,
  message text not null,
  http_request_id UUID references http_requests(id) on delete cascade,
  level server_log_entry_level not null
);