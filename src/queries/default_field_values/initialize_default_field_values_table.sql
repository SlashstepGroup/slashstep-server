DO $$
BEGIN

  CREATE TABLE IF NOT EXISTS default_field_values (
    id UUID DEFAULT uuidv7() PRIMARY KEY,
    field_id UUID NOT NULL REFERENCES fields(id) ON DELETE CASCADE,
    value_type field_value_type NOT NULL,
    text_value TEXT,
    number_value DECIMAL,
    boolean_value BOOLEAN,
    timestamp_value TIMESTAMPTZ,
    stakeholder_type stakeholder_type,
    stakeholder_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    stakeholder_group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    stakeholder_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    CONSTRAINT one_value_type CHECK (
      (value_type = 'Text' AND text_value IS NOT NULL)
      OR (value_type = 'Number' AND number_value IS NOT NULL)
      OR (value_type = 'Boolean' AND number_value IS NOT NULL)
      OR (value_type = 'Timestamp' AND timestamp_value IS NOT NULL)
      OR (value_type = 'Stakeholder' AND stakeholder_type IS NOT NULL AND (
        stakeholder_type = 'User' AND stakeholder_user_id IS NOT NULL
        OR stakeholder_type = 'Group' AND stakeholder_group_id IS NOT NULL
        OR stakeholder_type = 'App' AND stakeholder_app_id IS NOT NULL
      ))
    )
  );

END
$$ LANGUAGE plpgsql;
