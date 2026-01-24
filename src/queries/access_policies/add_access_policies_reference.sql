DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'action_log_entries_access_policies_fk') THEN
      ALTER TABLE action_log_entries ADD CONSTRAINT action_log_entries_access_policies_fk FOREIGN KEY (target_access_policy_id) REFERENCES access_policies(id);
    END IF;
  END
$$ LANGUAGE plpgsql;