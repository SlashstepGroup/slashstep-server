SELECT
  *
FROM
  groups
WHERE
  predefined_group_type = $1
  AND parent_resource_type = $2
  AND (
    parent_resource_type = 'Server' 
    OR parent_group_id = $3
  )
LIMIT 1;