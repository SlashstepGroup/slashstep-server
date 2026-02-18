DO $$
  BEGIN

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'configuration_value_type') THEN
      CREATE TYPE configuration_value_type AS ENUM (
        'Text',
        'Integer',
        'Decimal',
        'Boolean'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS configurations (
      id UUID PRIMARY KEY DEFAULT uuidv7(),
      name TEXT NOT NULL UNIQUE,
      value_type configuration_value_type NOT NULL,
      text_value TEXT,
      integer_value INTEGER,
      decimal_value DECIMAL,
      boolean_value BOOLEAN,
      CONSTRAINT value_type_match CHECK (
        (value_type = 'Text' AND integer_value IS NULL AND decimal_value IS NULL AND boolean_value IS NULL) OR
        (value_type = 'Integer' AND text_value IS NULL AND decimal_value IS NULL AND boolean_value IS NULL) OR
        (value_type = 'Decimal' AND text_value IS NULL AND integer_value IS NULL AND boolean_value IS NULL) OR
        (value_type = 'Boolean' AND text_value IS NULL AND integer_value IS NULL AND decimal_value IS NULL)
      )
    );

  END
$$ LANGUAGE plpgsql;