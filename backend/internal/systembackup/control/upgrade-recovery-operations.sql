-- Explicit control-database upgrade only. Never applied automatically.
CREATE TABLE IF NOT EXISTS system_backup_redis_plans (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 plan_json MEDIUMBLOB NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_redis_items (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 item_no BIGINT NOT NULL,
 item_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 item_state VARCHAR(24) NOT NULL,
 skipped BOOLEAN NOT NULL DEFAULT FALSE,
 proof_json MEDIUMBLOB,
 PRIMARY KEY(task_id,item_no)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_recovery_mutex (
 guard_id INT PRIMARY KEY
) ENGINE=InnoDB;
INSERT IGNORE INTO system_backup_recovery_mutex(guard_id) VALUES(1);
CREATE TABLE IF NOT EXISTS system_backup_recovery_guards (
 artifact_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 artifact_json MEDIUMBLOB NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_recovery_leases (
 artifact_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 consumer_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 generation BIGINT NOT NULL,
 until_ms BIGINT NOT NULL,
 released BOOLEAN NOT NULL DEFAULT FALSE,
 proof_json MEDIUMBLOB,
 PRIMARY KEY(artifact_id,task_id,consumer_id),
 INDEX task_active(task_id,released)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_v2_prune_runs (
 run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 plan_json MEDIUMBLOB NOT NULL,
 run_state VARCHAR(24) NOT NULL,
 INDEX task_state(task_id,run_state)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_v2_prune_items (
 run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 artifact_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 dispatch_json MEDIUMBLOB NOT NULL,
 item_state VARCHAR(24) NOT NULL,
 observation_json MEDIUMBLOB,
 PRIMARY KEY(run_id,artifact_id)
) ENGINE=InnoDB;
