-- Explicitly install only in the independent cm_backup_control_* database.
-- No automatic execution. Does not modify the application's business schema.
CREATE TABLE IF NOT EXISTS system_backup_catalog_actions (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_json MEDIUMBLOB NOT NULL,
 action_state VARCHAR(32) CHARACTER SET ascii NOT NULL,
 observation_json MEDIUMBLOB NULL,
 PRIMARY KEY(task_id,action_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_catalog_scans (
 scan_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state_json MEDIUMBLOB NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_catalog_records (
 scan_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 object_key VARBINARY(1024) NOT NULL,
 record_json MEDIUMBLOB NOT NULL,
 PRIMARY KEY(scan_id,key_hash)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_catalog_pages (
 scan_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 page_no BIGINT NOT NULL,
 page_json MEDIUMBLOB NOT NULL,
 PRIMARY KEY(scan_id,page_no)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_recovery_publications (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 result_json MEDIUMBLOB NOT NULL
) ENGINE=InnoDB;
