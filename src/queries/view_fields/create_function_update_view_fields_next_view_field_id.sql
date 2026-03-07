-- Ensures that the "next_view_field_id" of a view field is updated to point to the correct view field when a view field is inserted, updated, or deleted. This maintains the integrity of the linked list of view fields.
CREATE OR REPLACE FUNCTION update_view_field_next_view_field_ids() RETURNS TRIGGER AS $$

    BEGIN

        IF current_setting('view_fields.update_lock', TRUE) = '1' THEN

            RETURN NEW;

        END IF;

        PERFORM set_config('view_fields.update_lock', '1', TRUE);
        
        -- Update the former previous view field to point to the former next view field.
        UPDATE
            view_fields
        SET
            next_view_field_id = OLD.next_view_field_id
        WHERE
            view_fields.next_view_field_id = OLD.id;

        IF NEW.next_view_field_id IS NULL THEN

            -- Update the last view field in the table points to the current view field, making it second to last.
            UPDATE
                view_fields
            SET
                next_view_field_id = NEW.id
            WHERE
                next_view_field_id IS NULL AND id != NEW.id;

        ELSE

            -- Update the new previous view field to point to the current view field.
            UPDATE
                view_fields
            SET
                next_view_field_id = NEW.id
            WHERE
                next_view_field_id = NEW.next_view_field_id AND id != NEW.id;

        END IF;

        PERFORM set_config('view_fields.update_lock', '0', TRUE);

        RETURN NEW;

    END;

$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_view_field_next_view_field_ids_after_update
AFTER UPDATE ON view_fields
FOR EACH ROW
WHEN 
(OLD.next_view_field_id IS DISTINCT FROM NEW.next_view_field_id)
EXECUTE FUNCTION update_view_field_next_view_field_ids();

CREATE OR REPLACE TRIGGER update_view_field_next_view_field_ids_after_insert
AFTER INSERT ON view_fields
FOR EACH ROW
EXECUTE FUNCTION update_view_field_next_view_field_ids();

CREATE OR REPLACE TRIGGER update_view_field_next_view_field_ids_after_delete
AFTER DELETE ON view_fields
FOR EACH ROW
EXECUTE FUNCTION update_view_field_next_view_field_ids();