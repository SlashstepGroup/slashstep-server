DO $$
    BEGIN

        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_parent_resource_type') THEN
            CREATE TYPE action_parent_resource_type AS ENUM (
                'Instance',
                'App'
            );
        END IF;

        CREATE TABLE IF NOT EXISTS actions (
            id UUID DEFAULT uuidv7() PRIMARY KEY,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT NOT NULL,
            parent_app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
            parent_resource_type action_parent_resource_type NOT NULL
        );

    END
$$ LANGUAGE plpgsql;