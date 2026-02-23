do $$
begin

  CREATE TABLE IF NOT EXISTS delegation_policies (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    maximum_permission_level permission_level NOT NULL,
    delegate_app_authorization_id UUID REFERENCES app_authorizations(id) ON DELETE CASCADE,
    principal_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
  );

end
$$ LANGUAGE plpgsql;