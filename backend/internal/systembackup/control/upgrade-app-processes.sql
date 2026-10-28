-- Explicit upgrade for an existing cm_backup_control_* database only.
-- Never run against the application/reference database. Fresh installations
-- already have these definitions in schema.sql. No code auto-applies this file.
ALTER TABLE system_backup_mutations
 ADD COLUMN process_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 ADD INDEX process_permits(process_id);
CREATE TABLE IF NOT EXISTS system_backup_app_processes (
 process_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 identity_json BLOB NOT NULL,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 created_at_ms BIGINT NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_mutation_resolutions (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 process_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 permits_json MEDIUMBLOB NOT NULL,
 resolved_at_ms BIGINT NOT NULL
) ENGINE=InnoDB;
