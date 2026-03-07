DO $$

    BEGIN

        -- Ensures that the "next_status" of a status is updated to point to the correct status when a status is inserted, updated, or deleted. This maintains the integrity of the linked list of statuses.
        CREATE OR REPLACE FUNCTION update_statuses_next_status_id() RETURNS TRIGGER AS $func$

            BEGIN

                IF current_setting('view_fields.update_lock', TRUE) = '1' THEN

                    RETURN NEW;

                END IF;

                PERFORM set_config('view_fields.update_lock', '1', TRUE);
                
                -- Update the former previous status to point to the former next status.
                UPDATE
                    statuses
                SET
                    next_status_id = OLD.next_status_id
                WHERE
                    statuses.next_status_id = OLD.id;

                IF NEW.next_status_id IS NULL THEN

                    -- Update the last status in the table points to the current status, making it second to last.
                    UPDATE
                        statuses
                    SET
                        next_status_id = NEW.id
                    WHERE
                        next_status_id IS NULL AND id != NEW.id;

                ELSE

                    -- Update the new previous status to point to the current status.
                    UPDATE
                        statuses
                    SET
                        next_status_id = NEW.id
                    WHERE
                        next_status_id = NEW.next_status_id AND id != NEW.id;

                END IF;

                PERFORM set_config('statuses.update_lock', '0', TRUE);

                RETURN NEW;

            END;

        $func$ LANGUAGE plpgsql;

        CREATE OR REPLACE TRIGGER update_statuses_next_status_id_after_update
        AFTER UPDATE ON statuses
        FOR EACH ROW
        WHEN 
        (OLD.next_status_id IS DISTINCT FROM NEW.next_status_id)
        EXECUTE FUNCTION update_statuses_next_status_id();

        CREATE OR REPLACE TRIGGER update_statuses_next_status_id_after_insert
        AFTER INSERT ON statuses
        FOR EACH ROW
        EXECUTE FUNCTION update_statuses_next_status_id();

        CREATE OR REPLACE TRIGGER update_statuses_next_status_id_after_delete
        AFTER DELETE ON statuses
        FOR EACH ROW
        EXECUTE FUNCTION update_statuses_next_status_id();

    END;
    
$$ LANGUAGE plpgsql;