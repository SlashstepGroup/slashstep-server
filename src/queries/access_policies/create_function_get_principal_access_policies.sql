CREATE OR REPLACE FUNCTION get_principal_access_policies(
    parameter_principal_type principal_type, 
    parameter_principal_id UUID,
    parameter_action_id UUID, 
    parameter_resource_type resource_type, 
    parameter_resource_id UUID,
    needs_inheritance BOOLEAN
) RETURNS SETOF access_policies AS $$

    DECLARE
        variable_principal_user_id UUID;
        variable_principal_app_id UUID;
        variable_principal_group_id UUID;

    BEGIN

        IF parameter_principal_type = 'User' THEN

            variable_principal_user_id := parameter_principal_id;

        ELSIF parameter_principal_type = 'App' THEN

            variable_principal_app_id := parameter_principal_id;

        ELSIF parameter_principal_type = 'Group' THEN

            variable_principal_group_id := parameter_principal_id;

        ELSIF parameter_principal_type = 'Role' THEN

            RETURN QUERY
                SELECT
                    *
                FROM
                    access_policies
                WHERE
                    access_policies.principal_type = parameter_principal_type AND
                    access_policies.principal_role_id = parameter_principal_id;

        ELSE

            RAISE EXCEPTION 'Invalid principal type: %', parameter_principal_type;

        END IF;

        RETURN QUERY
            WITH RECURSIVE all_group_memberships AS (
                SELECT
                    variable_principal_user_id as root_principal_user_id,
                    variable_principal_app_id as root_principal_app_id,
                    variable_principal_group_id as root_principal_group_id,
                    group_memberships.parent_group_id,
                    group_memberships.principal_group_id
                FROM
                    memberships group_memberships
                WHERE
                    group_memberships.parent_resource_type = 'Group' AND
                    group_memberships.principal_type::TEXT = parameter_principal_type::TEXT AND (
                        group_memberships.principal_user_id = variable_principal_user_id OR 
                        group_memberships.principal_app_id = variable_principal_app_id OR 
                        group_memberships.principal_group_id = variable_principal_group_id
                    )
                UNION
                    SELECT
                        all_group_memberships.root_principal_user_id,
                        all_group_memberships.root_principal_app_id,
                        all_group_memberships.root_principal_group_id,
                        inherited_group_memberships.parent_group_id,
                        inherited_group_memberships.principal_group_id
                    FROM
                        memberships inherited_group_memberships
                    JOIN
                        all_group_memberships ON all_group_memberships.parent_group_id = inherited_group_memberships.principal_group_id
            )
            SELECT
                access_policies.*
            FROM
                access_policies
            LEFT JOIN
                all_group_memberships ON (
                    parameter_principal_type = 'User' AND
                    all_group_memberships.root_principal_user_id = variable_principal_user_id
                ) OR (
                    parameter_principal_type = 'App' AND
                    all_group_memberships.root_principal_app_id = variable_principal_app_id
                ) OR (
                    parameter_principal_type = 'Group' AND
                    all_group_memberships.root_principal_group_id = variable_principal_group_id
                )
            LEFT JOIN
                memberships role_memberships ON (
                    role_memberships.parent_resource_type = 'Role' AND (
                        role_memberships.principal_group_id = all_group_memberships.parent_group_id
                    ) OR (
                        parameter_principal_type = 'User' AND
                        role_memberships.principal_user_id = variable_principal_user_id
                    ) OR (
                        parameter_principal_type = 'App' AND
                        role_memberships.principal_app_id = variable_principal_app_id
                    )
                )
            WHERE
                (
                    (
                        parameter_principal_type = 'User' AND
                        access_policies.principal_user_id = variable_principal_user_id
                    ) OR (
                        parameter_principal_type = 'App' AND
                        access_policies.principal_app_id = variable_principal_app_id
                    ) OR
                    access_policies.principal_group_id = all_group_memberships.parent_group_id OR
                    access_policies.principal_role_id = role_memberships.parent_role_id
                ) AND 
                access_policies.action_id = parameter_action_id AND 
                access_policies.scoped_resource_type = parameter_resource_type AND (
                    access_policies.scoped_access_policy_id = parameter_resource_id OR
                    access_policies.scoped_action_id = parameter_resource_id OR
                    access_policies.scoped_action_log_entry_id = parameter_resource_id OR
                    access_policies.scoped_app_id = parameter_resource_id OR
                    access_policies.scoped_app_authorization_id = parameter_resource_id OR
                    access_policies.scoped_app_authorization_credential_id = parameter_resource_id OR
                    access_policies.scoped_app_credential_id = parameter_resource_id OR
                    access_policies.scoped_configuration_id = parameter_resource_id OR
                    access_policies.scoped_delegation_policy_id = parameter_resource_id OR
                    access_policies.scoped_field_id = parameter_resource_id OR
                    access_policies.scoped_field_choice_id = parameter_resource_id OR
                    access_policies.scoped_field_value_id = parameter_resource_id OR
                    access_policies.scoped_group_id = parameter_resource_id OR
                    access_policies.scoped_http_transaction_id = parameter_resource_id OR
                    access_policies.scoped_item_id = parameter_resource_id OR
                    access_policies.scoped_item_connection_id = parameter_resource_id OR
                    access_policies.scoped_item_connection_type_id = parameter_resource_id OR
                    access_policies.scoped_item_type_id = parameter_resource_id OR
                    access_policies.scoped_item_type_icon_id = parameter_resource_id OR
                    access_policies.scoped_iteration_id = parameter_resource_id OR
                    access_policies.scoped_membership_id = parameter_resource_id OR
                    access_policies.scoped_membership_invitation_id = parameter_resource_id OR
                    access_policies.scoped_milestone_id = parameter_resource_id OR
                    access_policies.scoped_oauth_authorization_id = parameter_resource_id OR
                    access_policies.scoped_password_reset_authorization_id = parameter_resource_id OR
                    access_policies.scoped_project_id = parameter_resource_id OR
                    access_policies.scoped_role_id = parameter_resource_id OR
                    access_policies.scoped_server_log_entry_id = parameter_resource_id OR
                    parameter_resource_type = 'Server' OR
                    access_policies.scoped_session_id = parameter_resource_id OR
                    access_policies.scoped_status_id = parameter_resource_id OR
                    access_policies.scoped_user_id = parameter_resource_id OR
                    access_policies.scoped_view_id = parameter_resource_id OR
                    access_policies.scoped_view_field_id = parameter_resource_id OR
                    access_policies.scoped_webhook_id = parameter_resource_id OR
                    access_policies.scoped_workspace_id = parameter_resource_id
                ) AND (
                    NOT needs_inheritance OR 
                    access_policies.is_inheritance_enabled
                );

    END;
$$ LANGUAGE plpgsql;