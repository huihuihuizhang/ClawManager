-- Resource and pause journals for the public runner. These reference the public
-- task/attempt; they are not another task state machine or a second business gate.
CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_resources (
 task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 namespace_name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_json MEDIUMBLOB NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 create_dispatched BOOLEAN NOT NULL DEFAULT FALSE,
 observed_uid VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 resource_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 lifecycle ENUM('creating','ready','deleting','deleted','absent') NOT NULL DEFAULT 'creating',
 process_json MEDIUMBLOB NULL,
 binding_json BLOB NULL,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 result_cipher MEDIUMBLOB NULL,
 result_key_ref VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
 result_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 stopped_at DATETIME(6) NULL,
 target_type ENUM('backup') NOT NULL DEFAULT 'backup',
 attempt_no INT UNSIGNED NOT NULL DEFAULT 1,
 phase ENUM('capture') NOT NULL DEFAULT 'capture',
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 PRIMARY KEY(task_public_id,resource_kind,namespace_name,resource_name),
 CONSTRAINT sbv2_runtime_resource_task FOREIGN KEY(task_public_id) REFERENCES system_backup_v2_backups(public_id) ON DELETE RESTRICT,
 CONSTRAINT sbv2_runtime_resource_attempt FOREIGN KEY(target_type,task_public_id,attempt_no,phase) REFERENCES system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) ON DELETE RESTRICT,
 CONSTRAINT sbv2_runtime_resource_json CHECK(JSON_VALID(CONVERT(request_json USING utf8mb4)) AND OCTET_LENGTH(request_json) BETWEEN 2 AND 1048576 AND request_sha256 REGEXP '^[a-f0-9]{64}$' AND row_version>=1),
 CONSTRAINT sbv2_runtime_resource_uid CHECK((observed_uid='' AND resource_version='') OR (observed_uid<>'' AND resource_version<>'' AND create_dispatched=TRUE))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_captures (
 task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 application_scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 gate_generation BIGINT UNSIGNED NOT NULL,
 acquire_token BIGINT UNSIGNED NOT NULL,
 held_token BIGINT UNSIGNED NULL,
 registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 writers_json MEDIUMBLOB NOT NULL,
 acquire_until DATETIME(6) NOT NULL,
 hold_until DATETIME(6) NOT NULL,
 collectors_stopped_at DATETIME(6) NULL,
 source_resumed_at DATETIME(6) NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 CONSTRAINT sbv2_runtime_capture_task FOREIGN KEY(task_public_id) REFERENCES system_backup_v2_backups(public_id) ON DELETE RESTRICT,
 CONSTRAINT sbv2_runtime_capture_identity CHECK(gate_generation>=1 AND registry_sha256 REGEXP '^[a-f0-9]{64}$' AND JSON_VALID(CONVERT(writers_json USING utf8mb4)) AND OCTET_LENGTH(writers_json) BETWEEN 2 AND 1048576),
 CONSTRAINT sbv2_runtime_capture_resume CHECK(source_resumed_at IS NULL OR collectors_stopped_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_writers (
 task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 writer_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 original_json MEDIUMBLOB NOT NULL,
 original_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 paused BOOLEAN NOT NULL DEFAULT FALSE,
 resumed BOOLEAN NOT NULL DEFAULT FALSE,
 row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
 PRIMARY KEY(task_public_id,writer_id),
 CONSTRAINT sbv2_runtime_writer_task FOREIGN KEY(task_public_id) REFERENCES system_backup_v2_backups(public_id) ON DELETE RESTRICT,
 CONSTRAINT sbv2_runtime_writer_json CHECK(JSON_VALID(CONVERT(original_json USING utf8mb4)) AND OCTET_LENGTH(original_json) BETWEEN 2 AND 1048576 AND original_sha256 REGEXP '^[a-f0-9]{64}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE system_backup_v2_execution_readiness
 ADD COLUMN execution_protocol VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'legacy',
 ADD COLUMN supported_parts SET('mysql','redis','object_storage','workspace','deployment_resources','secret_bundle') NOT NULL DEFAULT '',
 ADD COLUMN acceptance_ready BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_stop_proofs (
 task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pod_uid VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 proof_json MEDIUMBLOB NOT NULL,
 proof_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(task_public_id,pod_uid),
 CONSTRAINT sbv2_stop_proof_task FOREIGN KEY(task_public_id) REFERENCES system_backup_v2_backups(public_id) ON DELETE RESTRICT,
 CONSTRAINT sbv2_stop_proof_data CHECK(JSON_VALID(CONVERT(proof_json USING utf8mb4)) AND OCTET_LENGTH(proof_json) BETWEEN 2 AND 65536 AND proof_sha256 REGEXP '^[a-f0-9]{64}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
