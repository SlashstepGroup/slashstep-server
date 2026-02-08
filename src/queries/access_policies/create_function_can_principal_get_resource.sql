-- This function returns true if a principal can get a resource.
-- It's helpful for filtering access policies on the database level, making offsets more consistent.
CREATE OR REPLACE FUNCTION can_principal_get_resource(
    parameter_principal_type principal_type, 
    parameter_principal_id UUID,
    initial_resource_type resource_type, 
    initial_resource_id UUID, 
    get_resource_action_name TEXT
) RETURNS BOOLEAN AS $$

    DECLARE
        get_resource_action_id UUID;
        current_permission_Level permission_level;
        is_inheritance_enabled_on_selected_resource BOOLEAN;
        selected_resource_type access_policy_resource_type;
        selected_resource_id UUID;
        selected_resource_parent_type access_policy_resource_type;
        selected_resource_parent_id UUID;
        initial_access_policy access_policies%ROWTYPE;
        needs_inheritance BOOLEAN := FALSE;

    BEGIN

        -- Set the selected resource type and ID based on the principal type.
        get_resource_action_id := (
            SELECT
                id
            FROM
                actions
            WHERE
                name = get_resource_action_name
        );

        IF initial_resource_type = 'AccessPolicy' THEN

            SELECT
                scoped_resource_type
            INTO
                selected_resource_type
            FROM
                access_policies
            WHERE
                id = initial_resource_id
            LIMIT 1;

            SELECT
                *
            INTO
                initial_access_policy
            FROM
                access_policies
            WHERE
                id = initial_resource_id;

        ELSE

            selected_resource_type := initial_resource_type;

        END IF;

        selected_resource_id := 
            CASE
                WHEN initial_resource_type = 'AccessPolicy' THEN
                    get_initial_resource_id_from_access_policy(initial_access_policy)
                ELSE
                    initial_resource_id
            END;

        LOOP

            IF selected_resource_type = 'Server' THEN

                -- Server
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Server' AND (
                        NOT needs_inheritance OR 
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                RETURN current_permission_Level IS NOT NULL AND current_permission_Level >= 'User';

            ELSIF selected_resource_type = 'Action' THEN

                -- Action -> (App | Server)
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Action' AND 
                    principal_access_policies.scoped_action_id = selected_resource_id AND (
                        NOT needs_inheritance OR 
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    actions
                WHERE
                    actions.id = selected_resource_id;

                IF selected_resource_parent_type = 'App' THEN

                    SELECT
                        parent_app_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        actions
                    WHERE
                        actions.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent app for action %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'App';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Server' THEN

                    selected_resource_type := 'Server';
                    selected_resource_id := NULL;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for action %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'ActionLogEntry' THEN

                -- ActionLogEntry -> Server
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'ActionLogEntry' AND 
                    principal_access_policies.scoped_action_log_entry_id = selected_resource_id AND (
                        NOT needs_inheritance OR 
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'App' THEN

                -- App -> (Workspace | User | Server)
                -- Check if the app has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'App' AND 
                    principal_access_policies.scoped_app_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    parent_workspace_id
                INTO
                    selected_resource_parent_id
                FROM
                    apps
                WHERE
                    apps.id = selected_resource_id;

                IF selected_resource_parent_id IS NOT NULL THEN

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;
                    CONTINUE;

                END IF;

                SELECT
                    parent_user_id
                INTO
                    selected_resource_parent_id
                FROM
                    apps
                WHERE
                    apps.id = selected_resource_id;

                IF selected_resource_parent_id IS NOT NULL THEN

                    selected_resource_type := 'User';
                    selected_resource_id := selected_resource_parent_id;
                    CONTINUE;

                END IF;

                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'AppAuthorization' THEN

                -- AppAuthorization -> (User | Project | Workspace | Server)
                -- Check if the app authorization has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'AppAuthorization' AND 
                    principal_access_policies.scoped_app_authorization_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    authorizing_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    app_authorizations
                WHERE
                    app_authorizations.id = selected_resource_id;

                IF selected_resource_parent_type = 'User' THEN

                    SELECT
                        parent_user_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        app_authorizations
                    WHERE
                        app_authorizations.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent user for app authorization %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'User';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        authorizing_project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        app_authorizations
                    WHERE
                        app_authorizations.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for app authorization %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        app_authorizations
                    WHERE
                        app_authorizations.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for app authorization %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Server' THEN

                    selected_resource_type := 'Server';
                    selected_resource_id := NULL;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for action %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'AppAuthorizationCredential' THEN

                -- AppAuthorizationCredential -> AppAuthorization
                -- Check if the app authorization credential has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'AppAuthorizationCredential' AND 
                    principal_access_policies.scoped_app_authorization_credential_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    app_authorization_id
                INTO
                    selected_resource_parent_id
                FROM
                    app_authorization_credentials
                WHERE
                    app_authorization_credentials.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent app authorization for app authorization credential %.', selected_resource_id;

                END IF;

                selected_resource_type := 'AppAuthorization';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'AppCredential' THEN

                -- AppCredential -> App
                -- Check if the app credential has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'AppCredential' AND 
                    principal_access_policies.scoped_app_credential_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    app_id
                INTO
                    selected_resource_parent_id
                FROM
                    app_credentials
                WHERE
                    app_credentials.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent app for app credential %.', selected_resource_id;

                END IF;

                selected_resource_type := 'App';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Group' THEN

                -- Group -> Server
                -- Check if the group has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Group' AND 
                    principal_access_policies.scoped_group_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'HTTPTransaction' THEN

                -- HTTPTransaction -> Server
                -- Check if the HTTP transaction has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'HTTPTransaction' AND 
                    principal_access_policies.scoped_http_transaction_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'ServerLogEntry' THEN

                -- ServerLogEntry -> Server
                -- Check if the HTTP transaction log entry has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'ServerLogEntry' AND 
                    principal_access_policies.scoped_server_log_entry_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'Item' THEN

                -- Item -> Project
                -- Check if the item has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Item' AND 
                    principal_access_policies.scoped_item_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    project_id
                INTO
                    selected_resource_parent_id
                FROM
                    items
                WHERE
                    items.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for item %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Milestone' THEN

                -- Milestone -> (Project | Workspace)
                -- Check if the milestone has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Milestone' AND 
                    principal_access_policies.scoped_milestone_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    milestones
                WHERE
                    milestones.id = selected_resource_id;

                IF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        milestones
                    WHERE
                        milestones.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for milestone %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        milestones
                    WHERE
                        milestones.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for milestone %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Couldn''t find a parent resource for milestone %.', selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'Project' THEN

                -- Project -> Workspace
                -- Check if the project has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Project' AND 
                    principal_access_policies.scoped_project_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    parent_workspace_id
                INTO
                    selected_resource_parent_id
                FROM
                    projects
                WHERE
                    projects.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent workspace for project %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Workspace';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Role' THEN

                -- Role -> (Project | Workspace | Group | Server)
                -- Check if the role has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Role' AND 
                    principal_access_policies.scoped_role_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    roles
                WHERE
                    roles.id = selected_resource_id;

                IF selected_resource_parent_type = 'Server' THEN

                    selected_resource_type := 'Server';
                    selected_resource_id := NULL;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        roles
                    WHERE
                        roles.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for role %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        roles
                    WHERE
                        roles.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for role %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Group' THEN

                    SELECT
                        group_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        roles
                    WHERE
                        roles.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent group for role %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Group';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Couldn''t find a parent resource for role %.', selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'RoleMembership' THEN

                -- RoleMembership -> Role
                -- Check if the role membership has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'RoleMembership' AND 
                    principal_access_policies.scoped_role_membership_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    role_id
                INTO
                    selected_resource_parent_id
                FROM
                    role_memberships
                WHERE
                    role_memberships.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent role for role membership %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Role';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Session' THEN

                -- Session -> User
                -- Check if the session has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Session' AND 
                    principal_access_policies.scoped_session_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;

                SELECT
                    user_id
                INTO
                    selected_resource_parent_id
                FROM
                    sessions
                WHERE
                    sessions.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent user for session %.', selected_resource_id;

                END IF;

                selected_resource_type := 'User';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'User' THEN

                -- User -> Server
                -- Check if the user has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'User' AND 
                    principal_access_policies.scoped_user_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Look for the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'Workspace' THEN

                -- Workspace -> Server
                -- Check if the workspace has an associated access policy.
                SELECT
                    permission_level,
                    is_inheritance_enabled
                INTO
                    current_permission_Level,
                    is_inheritance_enabled_on_selected_resource
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, get_resource_action_id) principal_access_policies
                WHERE
                    principal_access_policies.scoped_resource_type = 'Workspace' AND 
                    principal_access_policies.scoped_workspace_id = selected_resource_id AND (
                        NOT needs_inheritance OR
                        principal_access_policies.is_inheritance_enabled
                    )
                LIMIT 1;

                IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                    RETURN FALSE;

                ELSIF current_permission_Level IS NOT NULL THEN

                    RETURN current_permission_Level >= 'User';

                END IF;

                -- Use the parent resource type.
                needs_inheritance := TRUE;
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSE

                RAISE EXCEPTION 'Unknown resource type: %', selected_resource_type;

            END IF;

        END LOOP;

    END;
$$ LANGUAGE plpgsql;