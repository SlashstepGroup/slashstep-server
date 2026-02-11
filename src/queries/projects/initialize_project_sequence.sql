create or replace function create_project_sequence(project_id UUID) returns void as $$
declare sequence_name text;
begin
  sequence_name := 'project_sequence_' || project_id;
  execute 'create sequence ' || quote_ident(sequence_name) || ' start with 1';
end;
$$ language plpgsql;