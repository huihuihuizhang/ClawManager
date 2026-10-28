-- D-owned current Job cursor and command-slot ledger. B owns status-relay
-- messages, Job-set identity and execution; relay wire values remain draft.
CREATE TABLE IF NOT EXISTS system_backup_job_observations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-job-observation.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_type ENUM('backup', 'drill', 'preflight', 'artifact_verify') NOT NULL,
  target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_no INT UNSIGNED NOT NULL,
  phase ENUM('capture', 'secret_capture', 'publish', 'restore', 'normalize', 'verify', 'preflight') NOT NULL,
  job_unit_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_uid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_generation BIGINT UNSIGNED NOT NULL,
  relay_identity_ref VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  relay_identity_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  relay_identity_bound_at DATETIME(6) NOT NULL,
  relay_identity_expires_at DATETIME(6) NOT NULL,
  last_accepted_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  last_accepted_body_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_observed_status VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_observed_at DATETIME(6) NULL,
  progress_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  progress_digest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_business_progress_at DATETIME(6) NULL,
  command_nonce CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  command_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  command_job_generation BIGINT UNSIGNED NULL,
  command_fencing_token BIGINT UNSIGNED NULL,
  command_created_at DATETIME(6) NULL,
  command_read_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_job_unit (origin_installation_id, target_type, target_public_id, attempt_no, phase, job_unit_key),
  UNIQUE KEY uk_sb_job_uid (job_uid),
  KEY idx_sb_job_attempt (target_type, target_public_id, attempt_no, phase),
  KEY idx_sb_job_stuck (origin_installation_id, last_business_progress_at, id),
  CONSTRAINT fk_sb_job_attempt FOREIGN KEY (target_type, target_public_id, attempt_no, phase) REFERENCES system_backup_attempts(target_type, target_public_id, attempt_no, phase) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_job_identity CHECK (
    schema_version = 'system-backup-job-observation.v1'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND job_unit_key REGEXP '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'
    AND job_uid REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND attempt_no >= 1 AND job_generation >= 1 AND row_version >= 1
  ),
  CONSTRAINT chk_sb_job_relay CHECK (
    CHAR_LENGTH(relay_identity_ref) BETWEEN 1 AND 256
    AND CHAR_LENGTH(relay_identity_version) BETWEEN 1 AND 128
    AND relay_identity_expires_at > relay_identity_bound_at
  ),
  CONSTRAINT chk_sb_job_cursor CHECK (
    (last_accepted_sequence = 0 AND last_accepted_body_sha256 IS NULL AND last_observed_status IS NULL AND last_observed_at IS NULL)
    OR (last_accepted_sequence > 0 AND last_accepted_body_sha256 IS NOT NULL AND last_accepted_body_sha256 REGEXP '^[0-9a-f]{64}$'
      AND last_observed_status IS NOT NULL AND last_observed_status REGEXP '^[a-z][a-z0-9_]{0,63}$' AND last_observed_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_job_progress CHECK (
    progress_sequence <= last_accepted_sequence
    AND ((progress_sequence = 0 AND progress_digest_sha256 IS NULL AND last_business_progress_at IS NULL)
      OR (progress_sequence > 0 AND progress_digest_sha256 IS NOT NULL AND progress_digest_sha256 REGEXP '^[0-9a-f]{64}$'
        AND last_business_progress_at IS NOT NULL AND last_observed_at IS NOT NULL AND last_business_progress_at <= last_observed_at))
  ),
  CONSTRAINT chk_sb_job_command CHECK (
    (command_nonce IS NULL AND command_sha256 IS NULL AND command_job_generation IS NULL AND command_fencing_token IS NULL AND command_created_at IS NULL AND command_read_at IS NULL)
    OR (phase IN ('capture', 'secret_capture') AND command_nonce IS NOT NULL AND command_nonce REGEXP '^[0-9a-f]{64}$'
      AND command_sha256 IS NOT NULL AND command_sha256 REGEXP '^[0-9a-f]{64}$'
      AND command_job_generation IS NOT NULL AND command_job_generation = job_generation
      AND command_fencing_token IS NOT NULL AND command_fencing_token >= 1 AND command_created_at IS NOT NULL
      AND (command_read_at IS NULL OR command_read_at >= command_created_at))
  ),
  CONSTRAINT chk_sb_job_times CHECK (
    updated_at >= created_at AND relay_identity_bound_at >= created_at
    AND (last_observed_at IS NULL OR last_observed_at >= relay_identity_bound_at)
    AND (command_created_at IS NULL OR command_created_at >= relay_identity_bound_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
