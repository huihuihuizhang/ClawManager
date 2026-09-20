-- D-owned restore-resource intent and cleanup inventory. B owns target-specific
-- resource kinds, creation, identity probes and provider deletion behavior.
CREATE TABLE IF NOT EXISTS system_restore_drill_resources (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-restore-drill-resource.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  drill_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  resource_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  planned_name VARCHAR(256) NOT NULL,
  observed_name VARCHAR(256) NULL,
  observed_uid VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  immutable_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  location_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_token_hmac CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_token_key_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lifecycle ENUM('creating', 'absent', 'created', 'deleting', 'deleted', 'delete_failed', 'ownership_unknown') NOT NULL DEFAULT 'creating',
  cleanup_operation_id BIGINT UNSIGNED NULL,
  ownership_resolution_operation_id BIGINT UNSIGNED NULL,
  ownership_resolution_evidence_id BIGINT UNSIGNED NULL,
  ownership_resolution_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_failure_code ENUM('none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch', 'checksum_mismatch', 'ownership_unknown', 'residual_data', 'internal') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  observed_at DATETIME(6) NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_restore_resource_public (public_id),
  UNIQUE KEY uk_sb_restore_resource_location (origin_installation_id, drill_public_id, resource_type, location_sha256),
  KEY idx_sb_restore_resource_drill (origin_installation_id, drill_public_id, created_at, id),
  KEY idx_sb_restore_resource_reconcile (origin_installation_id, lifecycle, next_reconcile_at, id),
  KEY idx_sb_restore_resource_cleanup (cleanup_operation_id),
  KEY idx_sb_restore_resource_resolution (ownership_resolution_operation_id),
  KEY idx_sb_restore_resource_evidence (ownership_resolution_evidence_id),
  CONSTRAINT fk_sb_restore_resource_drill FOREIGN KEY (origin_installation_id, drill_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_restore_resource_cleanup FOREIGN KEY (cleanup_operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_restore_resource_resolution FOREIGN KEY (ownership_resolution_operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_restore_resource_evidence FOREIGN KEY (ownership_resolution_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_restore_resource_identity CHECK (
    schema_version = 'system-restore-drill-resource.v1'
    AND public_id REGEXP '^srr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND drill_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND resource_type REGEXP '^[a-z][a-z0-9_]{0,63}$'
    AND CHAR_LENGTH(planned_name) BETWEEN 1 AND 256 AND row_version >= 1
  ),
  CONSTRAINT chk_sb_restore_resource_owner CHECK (
    location_sha256 REGEXP '^[0-9a-f]{64}$'
    AND owner_token_hmac REGEXP '^[0-9a-f]{64}$'
    AND CHAR_LENGTH(owner_token_key_version) BETWEEN 1 AND 128
  ),
  CONSTRAINT chk_sb_restore_resource_lifecycle CHECK (
    (lifecycle IN ('creating', 'absent', 'created', 'deleting', 'deleted') AND last_failure_code = 'none')
    OR (lifecycle = 'delete_failed' AND last_failure_code NOT IN ('none', 'ownership_unknown'))
    OR (lifecycle = 'ownership_unknown' AND last_failure_code = 'ownership_unknown')
  ),
  CONSTRAINT chk_sb_restore_resource_observed CHECK (
    (lifecycle NOT IN ('created', 'deleting', 'deleted', 'delete_failed') OR observed_name IS NOT NULL OR observed_uid IS NOT NULL OR immutable_version IS NOT NULL)
    AND (lifecycle <> 'absent' OR (observed_name IS NULL AND observed_uid IS NULL AND immutable_version IS NULL))
    AND (observed_name IS NULL OR CHAR_LENGTH(observed_name) BETWEEN 1 AND 256)
    AND (observed_uid IS NULL OR CHAR_LENGTH(observed_uid) BETWEEN 1 AND 256)
    AND (immutable_version IS NULL OR CHAR_LENGTH(immutable_version) BETWEEN 1 AND 256)
  ),
  CONSTRAINT chk_sb_restore_resource_evidence CHECK (
    (ownership_resolution_operation_id IS NULL AND ownership_resolution_evidence_id IS NULL AND ownership_resolution_evidence_sha256 IS NULL)
    OR (ownership_resolution_operation_id IS NOT NULL AND ownership_resolution_evidence_id IS NOT NULL
      AND ownership_resolution_evidence_sha256 IS NOT NULL AND ownership_resolution_evidence_sha256 REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_restore_resource_claim CHECK ((claim_owner IS NULL AND claim_expires_at IS NULL) OR (claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_restore_resource_time CHECK (
    updated_at >= created_at
    AND (observed_at IS NULL OR observed_at >= created_at)
    AND (claim_expires_at IS NULL OR claim_expires_at >= created_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
