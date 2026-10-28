-- Immutable encrypted observations; does not introduce a second task state.
CREATE TABLE IF NOT EXISTS system_backup_v2_execution_records (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_no INT UNSIGNED NOT NULL,
  phase ENUM('capture') NOT NULL,
  record_kind ENUM('plan', 'capture_result') NOT NULL,
  payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  key_ref VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  sealed_payload MEDIUMBLOB NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (origin_installation_id,task_public_id,attempt_no,phase,record_kind),
  CONSTRAINT fk_sb_execution_backup FOREIGN KEY (origin_installation_id,task_public_id)
    REFERENCES system_backup_v2_backups(origin_installation_id,public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_execution_payload CHECK (
    attempt_no > 0 AND payload_sha256 REGEXP '^[0-9a-f]{64}$'
    AND CHAR_LENGTH(key_ref) BETWEEN 1 AND 256
    AND OCTET_LENGTH(sealed_payload) BETWEEN 1 AND 8392704
  )
);
