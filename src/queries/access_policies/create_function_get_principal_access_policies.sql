CREATE OR REPLACE FUNCTION get_principal_access_policies(parameter_principal_type principal_type, parameter_principal_user_id UUID, parameter_principal_app_id UUID, get_access_policy_action_id UUID) RETURNS SETOF access_policies AS $$
  BEGIN

    RETURN QUERY
      WITH RECURSIVE all_group_memberships AS (
        SELECT
          parameter_principal_user_id as root_principal_user_id,
          parameter_principal_app_id as root_principal_app_id,
          group_memberships.group_id,
          group_memberships.principal_group_id
        FROM
          group_memberships
        WHERE
          group_memberships.principal_type::TEXT = parameter_principal_type::TEXT AND (
            (
              parameter_principal_type = 'User' AND
              group_memberships.principal_user_id = parameter_principal_user_id
            ) OR (
              parameter_principal_type = 'App' AND
              group_memberships.principal_app_id = parameter_principal_app_id
            )
          )
        UNION
          SELECT
            all_group_memberships.root_principal_user_id,
            all_group_memberships.root_principal_app_id,
            inherited_group_memberships.group_id,
            inherited_group_memberships.principal_group_id
          FROM
            group_memberships inherited_group_memberships
          JOIN
            all_group_memberships ON all_group_memberships.group_id = inherited_group_memberships.principal_group_id
      )
      SELECT
        access_policies.*
      FROM
        access_policies
      LEFT JOIN
        all_group_memberships ON (
          parameter_principal_type = 'User' AND
          all_group_memberships.root_principal_user_id = parameter_principal_user_id
        ) OR (
          parameter_principal_type = 'App' AND
          all_group_memberships.root_principal_app_id = parameter_principal_app_id
        )
      LEFT JOIN
        role_memberships ON (
          role_memberships.principal_group_id = all_group_memberships.group_id
        ) OR (
          parameter_principal_type = 'User' AND
          role_memberships.principal_user_id = parameter_principal_user_id
        ) OR (
          parameter_principal_type = 'App' AND
          role_memberships.principal_app_id = parameter_principal_app_id
        )
      WHERE
        (
          (
            parameter_principal_type = 'User' AND
            access_policies.principal_user_id = parameter_principal_user_id
          ) OR (
            parameter_principal_type = 'App' AND
            access_policies.principal_app_id = parameter_principal_app_id
          ) OR
          access_policies.principal_group_id = all_group_memberships.group_id OR
          access_policies.principal_role_id = role_memberships.role_id
        ) AND
        access_policies.action_id = get_access_policy_action_id
      ORDER BY
        CASE access_policies.principal_type
          WHEN 'User' THEN 1
          WHEN 'App' THEN 2
          WHEN 'Group' THEN 3
          WHEN 'Role' THEN 4
          ELSE 5
        END,
        CASE access_policies.permission_level
          WHEN 'Admin' THEN 1
          WHEN 'Editor' THEN 2
          WHEN 'User' THEN 3
          WHEN 'None' THEN 4
          ELSE 5
        END;

  END;
$$ LANGUAGE plpgsql;