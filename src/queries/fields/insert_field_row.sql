INSERT INTO fields (
  name,
  display_name,
  description,
  is_required,
  type,
  minimum_value,
  maximum_value,
  minimum_choice_count,
  maximum_choice_count,
  parent_project_id,
  is_deadline
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $10,
  $11
) RETURNING *;