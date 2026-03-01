insert into items (
  summary, 
  project_id, 
  number
) values (
  $1, 
  $2, 
  nextval('project_sequence_' || $3)
) returning *;