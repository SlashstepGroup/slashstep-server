SELECT
  *
FROM
  roles
WHERE
  predefined_role_type = $1
  AND parent_resource_type = $2
  AND (
    parent_resource_type = 'Server' 
    OR parent_group_id = $3
    OR parent_workspace_id = $3
    OR parent_project_id = $3
  )
LIMIT 1;