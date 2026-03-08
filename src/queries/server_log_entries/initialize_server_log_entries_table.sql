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

  CREATE TABLE IF NOT EXISTS server_log_entries (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    message TEXT NOT NULL,
    http_transaction_id UUID REFERENCES http_transactions(id),
    level server_log_entry_level NOT NULL
  );
end
$$ LANGUAGE plpgsql;