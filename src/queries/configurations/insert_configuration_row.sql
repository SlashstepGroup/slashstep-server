INSERT INTO configurations (
  name,
  value_type,
  text_value,
  integer_value,
  decimal_value,
  boolean_value
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;