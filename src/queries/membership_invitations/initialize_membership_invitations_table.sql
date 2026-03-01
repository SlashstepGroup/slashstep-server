do $$
begin

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'membership_invitation_invitee_principal_type') THEN
    CREATE TYPE membership_invitation_invitee_principal_type AS ENUM (
      'User',
      'App'
    );
  END IF;

  CREATE TABLE IF NOT EXISTS membership_invitations (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    parent_resource_type membership_parent_resource_type NOT NULL,
    parent_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    parent_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    inviter_principal_type membership_principal_type NOT NULL,
    inviter_principal_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    inviter_principal_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    invitee_principal_type membership_invitation_invitee_principal_type NOT NULL,
    invitee_principal_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    invitee_principal_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    invitee_principal_app_id UUID REFERENCES apps(id) ON DELETE CASCADE
  );

END
$$ LANGUAGE plpgsql;