DO $$

    BEGIN

        -- Verifies that the "next_view_field_id" of a row references another view field that is parented to the same view. 
        CREATE OR REPLACE FUNCTION verify_next_view_field_parent_view_id() RETURNS TRIGGER AS $func$
            
            DECLARE
                next_view_field_parent_view_id UUID;

            BEGIN

                IF NEW.next_view_field_id IS NULL OR OLD.next_view_field_id = NEW.next_view_field_id THEN

                    RETURN NEW;

                END IF;

                SELECT
                    parent_view_id
                INTO
                    next_view_field_parent_view_id
                FROM
                    view_fields
                WHERE
                    id = NEW.next_view_field_id;

                IF next_view_field_parent_view_id != NEW.parent_view_id THEN

                    RAISE EXCEPTION 'Next view fields must belong to the same parent view.';

                END IF;

                RETURN NEW;

            END;

        $func$ LANGUAGE plpgsql;

        CREATE OR REPLACE TRIGGER verify_next_view_field_parent_view_id_before_insert
        BEFORE INSERT ON view_fields
        FOR EACH ROW
        EXECUTE FUNCTION verify_next_view_field_parent_view_id();

        CREATE OR REPLACE TRIGGER verify_next_view_field_parent_view_id_before_update
        BEFORE UPDATE ON view_fields
        FOR EACH ROW
        EXECUTE FUNCTION verify_next_view_field_parent_view_id();

    END

$$ LANGUAGE plpgsql;