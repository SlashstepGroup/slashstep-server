DO $$
  BEGIN

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'configuration_value_type') THEN
      CREATE TYPE configuration_value_type AS ENUM (
        'Text',
        'Number',
        'Boolean'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS configurations (
      id UUID PRIMARY KEY DEFAULT uuidv7(),
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      value_type configuration_value_type NOT NULL,
      text_value TEXT,
      number_value DECIMAL,
      boolean_value BOOLEAN,
      default_text_value TEXT,
      default_number_value DECIMAL,
      default_boolean_value BOOLEAN
    );

  END
$$ LANGUAGE plpgsql;