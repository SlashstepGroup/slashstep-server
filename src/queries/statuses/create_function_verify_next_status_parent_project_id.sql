DO $$

    BEGIN

        -- Verifies that the "next_status_id" of a row references another status that is parented to the same project. 
        CREATE OR REPLACE FUNCTION verify_next_status_parent_project_id() RETURNS TRIGGER AS $func$
            
            DECLARE
                next_status_parent_project_id UUID;

            BEGIN

                IF NEW.next_status_id IS NULL OR OLD.next_status_id = NEW.next_status_id THEN

                    RETURN NEW;

                END IF;

                SELECT
                    parent_project_id
                INTO
                    next_status_parent_project_id
                FROM
                    statuses
                WHERE
                    id = NEW.next_status_id;

                IF next_status_parent_project_id != NEW.parent_project_id THEN

                    RAISE EXCEPTION 'Next statuses must belong to the same parent project.';

                END IF;

                RETURN NEW;

            END;

        $func$ LANGUAGE plpgsql;

        CREATE OR REPLACE TRIGGER verify_next_status_parent_project_id_before_insert
        BEFORE INSERT ON statuses
        FOR EACH ROW
        EXECUTE FUNCTION verify_next_status_parent_project_id();

        CREATE OR REPLACE TRIGGER verify_next_status_parent_project_id_before_update
        BEFORE UPDATE ON statuses
        FOR EACH ROW
        EXECUTE FUNCTION verify_next_status_parent_project_id();

    END

$$ LANGUAGE plpgsql;