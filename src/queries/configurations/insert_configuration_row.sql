INSERT INTO configurations (
  name,
  description,
  value_type,
  text_value,
  number_value,
  boolean_value,
  default_text_value,
  default_number_value,
  default_boolean_value
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9
) RETURNING *;