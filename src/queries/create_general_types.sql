DO $$
BEGIN

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'resource_type') THEN
    CREATE TYPE resource_type AS ENUM (
      'AccessPolicy',
      'Action',
      'ActionLogEntry',
      'App',
      'AppAuthorization',
      'AppAuthorizationCredential',
      'AppCredential',
      'Configuration',
      'DelegationPolicy',
      'Field',
      'FieldChoice',
      'FieldValue',
      'Group',
      'HTTPTransaction',
      'Server',
      'Item',
      'ItemConnection',
      'ItemConnectionType',
      'ItemType',
      'ItemTypeIcon',
      'Iteration',
      'Membership',
      'MembershipInvitation',
      'Milestone',
      'OAuthAuthorization',
      'PasswordResetAuthorization',
      'Project',
      'Role',
      'ServerLogEntry',
      'Session',
      'Status',
      'User',
      'View',
      'ViewField',
      'Webhook',
      'Workspace'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'stakeholder_type') THEN
    CREATE TYPE stakeholder_type AS ENUM (
      'User',
      'Group',
      'App'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'field_value_type') THEN
    CREATE TYPE field_value_type AS ENUM (
      'Text',
      'Number',
      'Boolean',
      'Timestamp',
      'Stakeholder',
      'Iteration',
      'Milestone'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'permission_level') THEN
    CREATE TYPE permission_level AS ENUM (
      'None',
      'User',
      'Editor',
      'Admin'
    );
  END IF;

END
$$ LANGUAGE plpgsql;