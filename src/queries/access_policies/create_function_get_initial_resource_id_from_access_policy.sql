CREATE OR REPLACE FUNCTION get_initial_resource_id_from_access_policy(access_policy_record access_policies) RETURNS UUID AS $$
  BEGIN

    CASE access_policy_record.scoped_resource_type
      WHEN 'Action' THEN 
        RETURN access_policy_record.scoped_action_id;
      WHEN 'ActionLogEntry' THEN 
        RETURN access_policy_record.scoped_action_log_entry_id;
      WHEN 'App' THEN 
        RETURN access_policy_record.scoped_app_id;
      WHEN 'AppAuthorization' THEN 
        RETURN access_policy_record.scoped_app_authorization_id;
      WHEN 'AppAuthorizationCredential' THEN 
        RETURN access_policy_record.scoped_app_authorization_credential_id;
      WHEN 'AppCredential' THEN 
        RETURN access_policy_record.scoped_app_credential_id;
      WHEN 'Field' THEN 
        RETURN access_policy_record.scoped_field_id;
      WHEN 'Group' THEN 
        RETURN access_policy_record.scoped_group_id;
      WHEN 'GroupMembership' THEN 
        RETURN access_policy_record.scoped_group_membership_id;
      WHEN 'HTTPTransaction' THEN 
        RETURN access_policy_record.scoped_http_transaction_id;
      WHEN 'Server' THEN 
        RETURN NULL;
      WHEN 'Item' THEN 
        RETURN access_policy_record.scoped_item_id;
      WHEN 'Milestone' THEN 
        RETURN access_policy_record.scoped_milestone_id;
      WHEN 'Project' THEN 
        RETURN access_policy_record.scoped_project_id;
      WHEN 'Role' THEN 
        RETURN access_policy_record.scoped_role_id;
      WHEN 'RoleMembership' THEN 
        RETURN access_policy_record.scoped_role_membership_id;
      WHEN 'ServerLogEntry' THEN 
        RETURN access_policy_record.scoped_server_log_entry_id;
      WHEN 'Session' THEN 
        RETURN access_policy_record.scoped_session_id;
      WHEN 'User' THEN 
        RETURN access_policy_record.scoped_user_id;
      WHEN 'Workspace' THEN 
        RETURN access_policy_record.scoped_workspace_id;
      ELSE
        RETURN NULL;
    END CASE;

  END;
$$ LANGUAGE plpgsql;