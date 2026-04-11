-- This function returns the permission level of a principal for a given resource.
-- It's helpful for filtering access policies on the database level, making offsets more consistent.
CREATE OR REPLACE FUNCTION get_principal_permission_level(
    parameter_principal_type principal_type, 
    parameter_principal_id UUID,
    initial_resource_type resource_type, 
    initial_resource_id UUID,
    parameter_action_id UUID
) RETURNS permission_level AS $$

    DECLARE
        primary_permission_level permission_level;
        selected_resource_type resource_type := initial_resource_type;
        selected_resource_id UUID := initial_resource_id;
        selected_resource_parent_type resource_type;
        selected_resource_parent_id UUID;
        selected_access_policy access_policies%ROWTYPE;
        needs_inheritance BOOLEAN := FALSE;
        bidirectional_resource_type resource_type;
        bidirectional_resource_id UUID;
        individual_permission_level permission_level;
        role_permission_level permission_level;
        group_permission_level permission_level;
        queued_resource_id UUID;
        queued_resource_type resource_type;
        can_update_individual_permission_level BOOLEAN := FALSE;
        can_update_role_permission_level BOOLEAN := FALSE;
        can_update_group_permission_level BOOLEAN := FALSE;
        original_permission_level permission_level;

    BEGIN

        IF parameter_principal_type != 'User' AND parameter_principal_type != 'App' THEN

            individual_permission_level := 'None';

        END IF;

        IF parameter_principal_type = 'Role' THEN

            group_permission_level := 'None';

        END IF;

        LOOP

            IF individual_permission_level IS NULL OR can_update_individual_permission_level THEN

                original_permission_level := individual_permission_level;

                SELECT
                    permission_level
                INTO
                    individual_permission_level
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, parameter_action_id, selected_resource_type, selected_resource_id, needs_inheritance) matching_access_policies
                WHERE
                    (
                        matching_access_policies.principal_type = 'User' OR
                        matching_access_policies.principal_type = 'App'
                    ) AND (
                        individual_permission_level IS NULL OR
                        matching_access_policies.permission_level > individual_permission_level
                    )
                ORDER BY
                    CASE matching_access_policies.permission_level
                        WHEN 'Admin' THEN 1
                        WHEN 'Editor' THEN 2
                        WHEN 'User' THEN 3
                        WHEN 'None' THEN 4
                        ELSE 5
                    END
                LIMIT 1;

                can_update_individual_permission_level = individual_permission_level IS NULL;
                individual_permission_level := COALESCE(individual_permission_level, original_permission_level);

            END IF;

            IF role_permission_level IS NULL OR can_update_role_permission_level THEN

                original_permission_level := role_permission_level;

                SELECT
                    permission_level
                INTO
                    role_permission_level
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, parameter_action_id, selected_resource_type, selected_resource_id, needs_inheritance) matching_access_policies
                WHERE
                    (
                        matching_access_policies.principal_type = 'User' OR
                        matching_access_policies.principal_type = 'App'
                    ) AND (
                        role_permission_level IS NULL OR
                        matching_access_policies.permission_level > role_permission_level
                    )
                ORDER BY
                    CASE matching_access_policies.permission_level
                        WHEN 'Admin' THEN 1
                        WHEN 'Editor' THEN 2
                        WHEN 'User' THEN 3
                        WHEN 'None' THEN 4
                        ELSE 5
                    END
                LIMIT 1;

                can_update_role_permission_level = role_permission_level IS NULL;
                role_permission_level := COALESCE(role_permission_level, original_permission_level);

            END IF;

            IF group_permission_level IS NULL OR can_update_group_permission_level THEN

                original_permission_level := group_permission_level;

                SELECT
                    permission_level
                INTO
                    group_permission_level
                FROM
                    get_principal_access_policies(parameter_principal_type, parameter_principal_id, parameter_action_id, selected_resource_type, selected_resource_id, needs_inheritance) matching_access_policies
                WHERE
                    (
                        matching_access_policies.principal_type = 'User' OR
                        matching_access_policies.principal_type = 'App'
                    ) AND (
                        group_permission_level IS NULL OR
                        matching_access_policies.permission_level > group_permission_level
                    )
                ORDER BY
                    CASE matching_access_policies.permission_level
                        WHEN 'Admin' THEN 1
                        WHEN 'Editor' THEN 2
                        WHEN 'User' THEN 3
                        WHEN 'None' THEN 4
                        ELSE 5
                    END
                LIMIT 1;

                can_update_group_permission_level = group_permission_level IS NULL;
                group_permission_level := COALESCE(group_permission_level, original_permission_level);

            END IF;

            IF (
                NOT can_update_individual_permission_level AND
                NOT can_update_role_permission_level AND
                NOT can_update_group_permission_level AND
                group_permission_level IS NOT NULL AND 
                role_permission_level IS NOT NULL AND 
                individual_permission_level IS NOT NULL
            ) THEN

                EXIT;

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            IF selected_resource_type = 'AccessPolicy' THEN

                -- AccessPolicy -> (AccessPolicy | Action | ActionLogEntry | App | AppAuthorization | AppAuthorizationCredential | AppCredential | Configuration | DelegationPolicy | Field | FieldChoice | FieldValue | Group | HTTPTransaction | Item | ItemConnection | ItemConnectionType | Membership | MembershipInvitation | Milestone | OAuthAuthorization | Project | Role | ServerLogEntry | Session | User | View | Workspace)
                SELECT
                    *
                INTO
                    selected_access_policy
                FROM
                    access_policies
                WHERE
                    access_policies.id = selected_resource_id;

                selected_resource_type := selected_access_policy.scoped_resource_type;
                selected_resource_id := get_scoped_resource_id_from_access_policy(selected_access_policy);
            
            ELSIF selected_resource_type = 'Server' THEN

                -- Server
                IF queued_resource_id IS NOT NULL THEN

                    selected_resource_type := queued_resource_type;
                    selected_resource_id := queued_resource_id;
                    queued_resource_id := NULL;
                    queued_resource_type := NULL;
                    can_update_individual_permission_level := TRUE;
                    can_update_role_permission_level := TRUE;
                    can_update_group_permission_level := TRUE;

                ELSE

                    EXIT;

                END IF;

            ELSIF selected_resource_type = 'Action' THEN

                -- Action -> (App | Server)
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
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'App' THEN

                -- App -> (Workspace | User | Server)
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

            ELSIF selected_resource_type = 'Configuration' THEN

                -- Configuration -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'DelegationPolicy' THEN

                -- DelegationPolicy -> User
                SELECT
                    principal_user_id
                INTO
                    selected_resource_parent_id
                FROM
                    delegation_policies
                WHERE
                    delegation_policies.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent user for delegation policy %.', selected_resource_id;

                END IF;

                selected_resource_type := 'User';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'FieldValue' THEN

                -- FieldValue -> (Item | Field)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    field_values
                WHERE
                    field_values.id = selected_resource_id;

                IF selected_resource_parent_type = 'Field' THEN

                    SELECT
                        parent_field_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        field_values
                    WHERE
                        field_values.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent field for field value %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Field';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Item' THEN

                    SELECT
                        parent_item_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        field_values
                    WHERE
                        field_values.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent item for field value %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Item';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for field value %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'Field' THEN

                -- Field -> Project
                SELECT
                    parent_project_id
                INTO
                    selected_resource_parent_id
                FROM
                    fields
                WHERE
                    fields.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for field %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'FieldChoice' THEN

                -- FieldChoice -> Field
                SELECT
                    field_id
                INTO
                    selected_resource_parent_id
                FROM
                    field_choices
                WHERE
                    field_choices.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent field for field choice %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Field';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Group' THEN

                -- Group -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'HTTPTransaction' THEN

                -- HTTPTransaction -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'ServerLogEntry' THEN

                -- ServerLogEntry -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'Item' THEN

                -- Item -> Project
                SELECT
                    parent_project_id
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

            ELSIF selected_resource_type = 'ItemConnection' THEN

                -- ItemConnection -> Item + Item
                -- Since item connections are bidirectional, we need to check both the inward and outward item.
                SELECT
                    inward_item_id,
                    outward_item_id
                INTO
                    selected_resource_parent_id,
                    queued_resource_id
                FROM
                    item_connections
                WHERE
                    item_connections.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find an inward item for item connection %.', selected_resource_id;

                END IF;

                IF queued_resource_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find an outward item for item connection %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Item';
                selected_resource_id := selected_resource_parent_id;
                queued_resource_type := 'Item';

            ELSIF selected_resource_type = 'ItemConnectionType' THEN

                -- ItemConnectionType -> (Project | Workspace)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    item_connection_types
                WHERE
                    item_connection_types.id = selected_resource_id;

                IF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        parent_project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        item_connection_types
                    WHERE
                        item_connection_types.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for item connection type %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        item_connection_types
                    WHERE
                        item_connection_types.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for item connection type %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Couldn''t find a parent resource for item connection type %.', selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'ItemType' THEN

                -- ItemType -> Project
                SELECT
                    parent_project_id
                INTO
                    selected_resource_parent_id
                FROM
                    item_types
                WHERE
                    item_types.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for item type %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'ItemTypeIcon' THEN

                -- ItemTypeIcon -> (Project | Server)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    item_type_icons
                WHERE
                    item_type_icons.id = selected_resource_id;

                IF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        parent_project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        item_type_icons
                    WHERE
                        item_type_icons.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for item type icon %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Server' THEN

                    selected_resource_type := 'Server';
                    selected_resource_id := NULL;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for item type icon %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'Iteration' THEN

                -- Iteration -> Project
                SELECT
                    parent_project_id
                INTO
                    selected_resource_parent_id
                FROM
                    iterations
                WHERE
                    iterations.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for iteration %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Membership' THEN

                -- Membership -> (Group | Role)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    memberships
                WHERE
                    memberships.id = selected_resource_id;

                IF selected_resource_parent_type = 'Group' THEN

                    SELECT
                        parent_group_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        memberships
                    WHERE
                        memberships.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent group for membership %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Group';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Role' THEN

                    SELECT
                        parent_role_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        memberships
                    WHERE
                        memberships.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent role for membership %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Role';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for membership %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'MembershipInvitation' THEN

                -- MembershipInvitation -> (Group | Role)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    membership_invitations
                WHERE
                    membership_invitations.id = selected_resource_id;

                IF selected_resource_parent_type = 'Group' THEN

                    SELECT
                        parent_group_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        membership_invitations
                    WHERE
                        membership_invitations.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent group for membership invitation %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Group';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Role' THEN

                    SELECT
                        parent_role_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        membership_invitations
                    WHERE
                        membership_invitations.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent role for membership invitation %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Role';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for membership invitation %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'Milestone' THEN

                -- Milestone -> (Project | Workspace)
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
                        parent_project_id
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

            ELSIF selected_resource_type = 'OAuthAuthorization' THEN

                -- OAuthAuthorization -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'Project' THEN

                -- Project -> Workspace
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
                        parent_project_id
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
                        parent_group_id
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

            ELSIF selected_resource_type = 'Session' THEN

                -- Session -> User
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

            ELSIF selected_resource_type = 'Status' THEN

                -- Status -> Project
                SELECT
                    parent_project_id
                INTO
                    selected_resource_parent_id
                FROM
                    statuses
                WHERE
                    statuses.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for status %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'User' THEN

                -- User -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSIF selected_resource_type = 'View' THEN

                -- View -> (Project | Workspace)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    views
                WHERE
                    views.id = selected_resource_id;

                IF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        parent_project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        views
                    WHERE
                        views.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for view %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        views
                    WHERE
                        views.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for view %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Couldn''t find a parent resource for view %.', selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'ViewField' THEN

                -- ViewField -> View
                SELECT
                    parent_view_id
                INTO
                    selected_resource_parent_id
                FROM
                    view_fields
                WHERE
                    view_fields.id = selected_resource_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent view for view field %.', selected_resource_id;

                END IF;

                selected_resource_type := 'View';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_type = 'Webhook' THEN

                -- Webhook -> (App | Group | Project | Server | User | Workspace)
                SELECT
                    parent_resource_type
                INTO
                    selected_resource_parent_type
                FROM
                    webhooks
                WHERE
                    webhooks.id = selected_resource_id;

                IF selected_resource_parent_type = 'App' THEN

                    SELECT
                        parent_app_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        webhooks
                    WHERE
                        webhooks.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent app for webhook %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'App';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Group' THEN

                    SELECT
                        parent_group_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        webhooks
                    WHERE
                        webhooks.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent group for webhook %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Group';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Project' THEN

                    SELECT
                        parent_project_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        webhooks
                    WHERE
                        webhooks.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent project for webhook %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Project';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Server' THEN

                    selected_resource_type := 'Server';
                    selected_resource_id := NULL;

                ELSIF selected_resource_parent_type = 'User' THEN

                    SELECT
                        parent_user_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        webhooks
                    WHERE
                        webhooks.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent user for webhook %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'User';
                    selected_resource_id := selected_resource_parent_id;

                ELSIF selected_resource_parent_type = 'Workspace' THEN

                    SELECT
                        parent_workspace_id
                    INTO
                        selected_resource_parent_id
                    FROM
                        webhooks
                    WHERE
                        webhooks.id = selected_resource_id;

                    IF selected_resource_parent_id IS NULL THEN

                        RAISE EXCEPTION 'Couldn''t find a parent workspace for webhook %.', selected_resource_id;

                    END IF;

                    selected_resource_type := 'Workspace';
                    selected_resource_id := selected_resource_parent_id;

                ELSE

                    RAISE EXCEPTION 'Unknown parent resource type % for webhook %.', selected_resource_parent_type, selected_resource_id;

                END IF;

            ELSIF selected_resource_type = 'Workspace' THEN

                -- Workspace -> Server
                selected_resource_type := 'Server';
                selected_resource_id := NULL;

            ELSE

                RAISE EXCEPTION 'Unknown resource type: %', selected_resource_type;

            END IF;

        END LOOP;

        SELECT 
            COALESCE(individual_permission_level, role_permission_level, group_permission_level, 'None') 
        INTO 
            primary_permission_level;

        RETURN primary_permission_level;

    END;
    
$$ LANGUAGE plpgsql;