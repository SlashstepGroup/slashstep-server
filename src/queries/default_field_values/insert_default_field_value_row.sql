INSERT INTO default_field_values (
  field_id,
  value_type,
  text_value,
  number_value,
  boolean_value,
  timestamp_value,
  stakeholder_type,
  stakeholder_user_id,
  stakeholder_group_id,
  stakeholder_app_id
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
  $10
) RETURNING *;