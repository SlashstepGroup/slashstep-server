INSERT INTO field_values (
  field_id,
  parent_resource_type,
  parent_field_id,
  parent_item_id,
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
  $10,
  $11,
  $12,
  $13
) RETURNING *;