-- Execution readiness is separate from control-loop health. A watchdog being
-- healthy must never authorize tasks when no concrete execution adapter exists.
CREATE TABLE IF NOT EXISTS system_backup_v2_execution_readiness (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('backup','preflight') NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  profile_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  generation BIGINT UNSIGNED NOT NULL,
  ready BOOLEAN NOT NULL DEFAULT FALSE,
  checked_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY(origin_installation_id,task_type),
  CONSTRAINT sbv2_fk_execution_config FOREIGN KEY(origin_installation_id,config_version)
    REFERENCES system_backup_v2_configs(origin_installation_id,version) ON DELETE RESTRICT,
  CONSTRAINT sbv2_chk_execution_profile CHECK(profile_sha256 REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT sbv2_chk_execution_owner CHECK(owner REGEXP '^[A-Za-z0-9._:-]{1,128}$' AND generation>=1),
  CONSTRAINT sbv2_chk_execution_time CHECK(expires_at>checked_at AND expires_at<=TIMESTAMPADD(SECOND,60,checked_at))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Immutable execution input, committed with the task. No provider work occurs
-- before the transaction commits. Raw credentials/paths are not request fields.
CREATE TABLE IF NOT EXISTS system_backup_v2_execution_inputs (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('backup','preflight') NOT NULL,
  profile_json MEDIUMBLOB NOT NULL,
  profile_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_json BLOB NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY(origin_installation_id,task_public_id),
  CONSTRAINT sbv2_fk_execution_installation FOREIGN KEY(origin_installation_id)
    REFERENCES system_backup_v2_installation_state(origin_installation_id) ON DELETE RESTRICT,
  CONSTRAINT sbv2_chk_execution_input_hash CHECK(profile_sha256 REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT sbv2_chk_execution_input_json CHECK(OCTET_LENGTH(profile_json) BETWEEN 2 AND 16384 AND JSON_VALID(CONVERT(profile_json USING utf8mb4)) AND OCTET_LENGTH(request_json) BETWEEN 2 AND 16384 AND JSON_VALID(CONVERT(request_json USING utf8mb4)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
