-- Outbound Job send intent precedes the API call. A lost create response must
-- resolve this exact name/spec; absence after sending is not permission to retry.
CREATE TABLE IF NOT EXISTS system_backup_v2_job_send_intents (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_type ENUM('backup') NOT NULL DEFAULT 'backup',
  phase ENUM('capture','secret_capture','publish') NOT NULL,
  job_unit_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_no INT UNSIGNED NOT NULL DEFAULT 1,
  namespace_name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  namespace_uid VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_name VARCHAR(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  spec_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  send_state ENUM('planned','sending','bound') NOT NULL DEFAULT 'planned',
  job_uid VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  send_started_at DATETIME(6) NULL,
  bound_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY(origin_installation_id,task_public_id,phase,job_unit_key),
  UNIQUE KEY uk_sbv2_job_send_name(namespace_uid,job_name),
  CONSTRAINT sbv2_fk_job_send_plan FOREIGN KEY(origin_installation_id,task_public_id)
    REFERENCES system_backup_v2_execution_plans(origin_installation_id,task_public_id) ON DELETE RESTRICT,
  CONSTRAINT sbv2_fk_job_send_attempt FOREIGN KEY(target_type,task_public_id,attempt_no,phase)
    REFERENCES system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) ON DELETE RESTRICT,
  CONSTRAINT sbv2_chk_job_send_hash CHECK(spec_sha256 REGEXP '^[0-9a-f]{64}$' AND attempt_no=1),
  CONSTRAINT sbv2_chk_job_send_unit CHECK(job_unit_key REGEXP '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'),
  CONSTRAINT sbv2_chk_job_send_state CHECK(
    (send_state='planned' AND job_uid IS NULL AND send_started_at IS NULL AND bound_at IS NULL)
    OR (send_state='sending' AND job_uid IS NULL AND send_started_at IS NOT NULL AND bound_at IS NULL)
    OR (send_state='bound' AND job_uid IS NOT NULL AND send_started_at IS NOT NULL AND bound_at IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
