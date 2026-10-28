-- Install only in the separately configured cm_backup_control_* schema.
-- For an EXISTING schema from before source restart integration. Fresh installs
-- use schema.sql, which already includes this column. Never run automatically.
ALTER TABLE system_backup_pauses ADD COLUMN restart_result MEDIUMBLOB NULL;
