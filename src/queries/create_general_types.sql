DO $$
BEGIN

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
      'Stakeholder'
    );
  END IF;

END
$$ LANGUAGE plpgsql;