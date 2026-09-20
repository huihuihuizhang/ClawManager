-- D-owned backup staging inventory. Resource creation/deletion remains B's
-- runner/provider responsibility; this table records the controller intent and
-- authoritative lifecycle before any external creation is attempted.
CREATE TABLE IF NOT EXISTS system_backup_staging_resources (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-staging-resource.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  backup_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_no INT UNSIGNED NOT NULL,
  phase ENUM('capture', 'secret_capture', 'publish') NOT NULL,
  phase_uid VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  resource_type ENUM('pvc', 'hostpath', 'remote_manifest_candidate') NOT NULL,
  planned_locator VARCHAR(1024) NOT NULL,
  location_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_marker_hmac CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_marker_key_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observed_name VARCHAR(256) NULL,
  observed_uid VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  immutable_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  candidate_checksum_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  candidate_length_bytes INT UNSIGNED NULL,
  lifecycle ENUM('creating', 'absent', 'ready', 'sealed', 'deleting', 'deleted', 'delete_failed', 'ownership_unknown') NOT NULL DEFAULT 'creating',
  cleanup_result ENUM('not_started', 'running', 'succeeded', 'failed') NOT NULL DEFAULT 'not_started',
  last_failure_code ENUM('none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch', 'checksum_mismatch', 'ownership_unknown', 'residual_data', 'internal') NOT NULL DEFAULT 'none',
  cleanup_operation_id BIGINT UNSIGNED NULL,
  ownership_resolution_operation_id BIGINT UNSIGNED NULL,
  ownership_resolution_evidence_id BIGINT UNSIGNED NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_staging_public (public_id),
  UNIQUE KEY uk_sb_staging_locator (origin_installation_id, location_sha256),
  KEY idx_sb_staging_backup (origin_installation_id, backup_public_id, created_at, id),
  KEY idx_sb_staging_reconcile (origin_installation_id, lifecycle, next_reconcile_at, id),
  KEY idx_sb_staging_cleanup_operation (cleanup_operation_id),
  KEY idx_sb_staging_resolution_operation (ownership_resolution_operation_id),
  KEY idx_sb_staging_resolution_evidence (ownership_resolution_evidence_id),
  CONSTRAINT fk_sb_staging_backup FOREIGN KEY (origin_installation_id, backup_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_staging_cleanup_operation FOREIGN KEY (cleanup_operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_staging_resolution_operation FOREIGN KEY (ownership_resolution_operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_staging_resolution_evidence FOREIGN KEY (ownership_resolution_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_staging_identity CHECK (
    schema_version = 'system-backup-staging-resource.v1'
    AND public_id REGEXP '^sbs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND backup_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND attempt_no >= 1 AND CHAR_LENGTH(phase_uid) BETWEEN 1 AND 128 AND row_version >= 1
  ),
  CONSTRAINT chk_sb_staging_locator CHECK (
    CHAR_LENGTH(planned_locator) BETWEEN 1 AND 1024
    AND location_sha256 REGEXP '^[0-9a-f]{64}$'
    AND owner_marker_hmac REGEXP '^[0-9a-f]{64}$'
    AND CHAR_LENGTH(owner_marker_key_version) BETWEEN 1 AND 128
  ),
  CONSTRAINT chk_sb_staging_phase CHECK (
    (resource_type IN ('pvc', 'hostpath') AND phase IN ('capture', 'secret_capture'))
    OR (resource_type = 'remote_manifest_candidate' AND phase = 'publish')
  ),
  CONSTRAINT chk_sb_staging_candidate CHECK (
    (resource_type = 'remote_manifest_candidate' AND (
      (candidate_checksum_sha256 IS NULL AND candidate_length_bytes IS NULL)
      OR (candidate_checksum_sha256 IS NOT NULL AND candidate_checksum_sha256 REGEXP '^[0-9a-f]{64}$' AND candidate_length_bytes IS NOT NULL AND candidate_length_bytes BETWEEN 1 AND 262144)
    ))
    OR (resource_type <> 'remote_manifest_candidate' AND candidate_checksum_sha256 IS NULL AND candidate_length_bytes IS NULL)
  ),
  CONSTRAINT chk_sb_staging_lifecycle CHECK (
    (lifecycle IN ('creating', 'ready', 'sealed') AND cleanup_result = 'not_started' AND last_failure_code = 'none')
    OR (lifecycle = 'deleting' AND cleanup_result = 'running' AND last_failure_code = 'none')
    OR (lifecycle IN ('absent', 'deleted') AND cleanup_result = 'succeeded' AND last_failure_code = 'none')
    OR (lifecycle = 'delete_failed' AND cleanup_result = 'failed' AND last_failure_code NOT IN ('none', 'ownership_unknown'))
    OR (lifecycle = 'ownership_unknown' AND cleanup_result = 'failed' AND last_failure_code = 'ownership_unknown')
  ),
  CONSTRAINT chk_sb_staging_observed CHECK (
    (lifecycle NOT IN ('ready', 'sealed', 'deleting', 'deleted', 'delete_failed') OR observed_name IS NOT NULL OR observed_uid IS NOT NULL OR immutable_version IS NOT NULL)
    AND (resource_type <> 'remote_manifest_candidate' OR lifecycle <> 'sealed' OR (immutable_version IS NOT NULL AND candidate_checksum_sha256 IS NOT NULL AND candidate_length_bytes IS NOT NULL))
    AND (lifecycle <> 'absent' OR (observed_name IS NULL AND observed_uid IS NULL AND immutable_version IS NULL))
  ),
  CONSTRAINT chk_sb_staging_operations CHECK (
    (ownership_resolution_operation_id IS NULL AND ownership_resolution_evidence_id IS NULL)
    OR (ownership_resolution_operation_id IS NOT NULL AND ownership_resolution_evidence_id IS NOT NULL)
  ),
  CONSTRAINT chk_sb_staging_claim CHECK ((claim_owner IS NULL AND claim_expires_at IS NULL) OR (claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_staging_times CHECK (updated_at >= created_at AND (claim_expires_at IS NULL OR claim_expires_at >= created_at))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
