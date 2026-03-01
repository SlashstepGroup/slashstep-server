insert into items (
  summary, 
  parent_project_id, 
  number
) values (
  $1, 
  $2, 
  nextval('project_sequence_' || $3)
) returning *;