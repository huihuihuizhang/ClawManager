-- A durable UTC admission-wait origin on the authoritative public task.
-- NULL means this deployment has not observed its first source-gate attempt;
-- do not backdate historical tasks or restart the budget on controller takeover.
ALTER TABLE system_backup_v2_backups
 ADD COLUMN source_gate_wait_started_at DATETIME(6) NULL;
