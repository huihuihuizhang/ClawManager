-- Shared control journal, explicitly installed in the CONTROL database.
-- Not an application migration; never apply this file to a reference source.
CREATE TABLE IF NOT EXISTS system_backup_tasks (
 public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id BIGINT NOT NULL,
 idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii NOT NULL,
 request_json MEDIUMBLOB NOT NULL,
 profile_revision CHAR(64) CHARACTER SET ascii NOT NULL,
 status VARCHAR(32) NOT NULL,
 can_cancel BOOLEAN NOT NULL,
 row_version BIGINT NOT NULL,
 generation BIGINT NOT NULL,
 controller_owner VARCHAR(128) NOT NULL DEFAULT '',
 controller_lease_until BIGINT NOT NULL DEFAULT 0,
 created_at_ms BIGINT NOT NULL,
 deadline_ms BIGINT NOT NULL,
 failure_code VARCHAR(64) NOT NULL DEFAULT '',
 UNIQUE KEY request_once(actor_id,idempotency_key),
 KEY takeover(status,controller_lease_until)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_v2_events (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 row_version BIGINT NOT NULL,
 code VARCHAR(64) NOT NULL,
 created_at_ms BIGINT NOT NULL,
 UNIQUE KEY event_once(task_id,row_version)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_maintenance (
 id INT PRIMARY KEY,
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 generation BIGINT NOT NULL DEFAULT 0,
 closed BOOLEAN NOT NULL DEFAULT FALSE,
 hold_until_ms BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB;
INSERT IGNORE INTO system_backup_maintenance(id) VALUES(1);
CREATE TABLE IF NOT EXISTS system_backup_mutations (
 token VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 participant VARCHAR(128) NOT NULL,
 process_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 created_at_ms BIGINT NOT NULL,
 KEY process_permits(process_id)
) ENGINE=InnoDB;
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
CREATE TABLE IF NOT EXISTS system_backup_pauses (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 writer_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 ordinal BIGINT NOT NULL,
 original_json MEDIUMBLOB NOT NULL,
 acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
 resumed BOOLEAN NOT NULL DEFAULT FALSE,
 restart_dispatched BOOLEAN NOT NULL DEFAULT FALSE,
 restart_result MEDIUMBLOB NULL,
 PRIMARY KEY(task_id,writer_id),
 UNIQUE KEY pause_order(task_id,ordinal)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_profiles (
 profile_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 profile_json MEDIUMBLOB NOT NULL,
 valid_until_ms BIGINT NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_capture_registry (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 registry_json MEDIUMBLOB NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_resources (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 namespace_name VARCHAR(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_marker VARCHAR(256) NOT NULL,
 request_sha256 CHAR(64) NOT NULL,
 request_json MEDIUMBLOB NOT NULL,
 row_version BIGINT NOT NULL,
 dispatched BOOLEAN NOT NULL,
 uid VARCHAR(256) NOT NULL,
 resource_version VARCHAR(256) NOT NULL,
 lifecycle VARCHAR(32) NOT NULL,
 PRIMARY KEY(task_id,kind,namespace_name,resource_name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_workers (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 invocation_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 spiffe_uri VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 grant_json MEDIUMBLOB NOT NULL,
 ready BOOLEAN NOT NULL DEFAULT FALSE,
 acquired_until_ms BIGINT NOT NULL DEFAULT 0,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 terminated BOOLEAN NOT NULL DEFAULT FALSE,
 result_json MEDIUMBLOB NULL,
 PRIMARY KEY(task_id,invocation_sha256),
 UNIQUE KEY worker_identity(spiffe_uri)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_publications (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 intent_json MEDIUMBLOB NOT NULL,
 published_sha256 CHAR(64) CHARACTER SET ascii NOT NULL,
 committed BOOLEAN NOT NULL DEFAULT FALSE,
 commit_started_at_ms BIGINT NOT NULL DEFAULT 0,
 confirmed_at_ms BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_private_records (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 key_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 nonce VARBINARY(12) NOT NULL,
 ciphertext MEDIUMBLOB NOT NULL,
 PRIMARY KEY(task_id,record_name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_identities (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 secret_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 namespace_name VARCHAR(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 payload_sha256 CHAR(64) CHARACTER SET ascii NOT NULL,
 dispatched BOOLEAN NOT NULL DEFAULT FALSE,
 uid VARCHAR(256) NOT NULL DEFAULT '',
 resource_version VARCHAR(256) NOT NULL DEFAULT '',
 deleted BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(task_id,secret_name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_credentials (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 credential_ref VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 active BOOLEAN NOT NULL DEFAULT FALSE,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 removed BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(task_id,credential_ref)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_worker_processes (
 task_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 invocation_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 process_json MEDIUMBLOB NOT NULL,
 PRIMARY KEY(task_id,invocation_sha256)
) ENGINE=InnoDB;
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
