CREATE TABLE IF NOT EXISTS system_backup_promotions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-promotion.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  matrix_key ENUM('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node') NOT NULL,
  record_status ENUM('active', 'superseded', 'revoked') NOT NULL DEFAULT 'active',
  active_guard TINYINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN record_status = 'active' THEN 1 ELSE NULL END) STORED,
  backup_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  drill_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  manifest_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  acceptance_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_registration_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_registration_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  eligibility_decision_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  drill_evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  drill_evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_backup_row_version BIGINT UNSIGNED NOT NULL,
  source_drill_row_version BIGINT UNSIGNED NOT NULL,
  source_prune_guard_version BIGINT UNSIGNED NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  creation_artifact_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_artifact_access_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_kek_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_signature_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_catalog_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_evidence_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_attestation_health ENUM('healthy', 'degraded', 'unknown', 'stale') NOT NULL,
  creation_health_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  creation_health_observed_at DATETIME(6) NOT NULL,
  created_by VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  superseded_by_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  superseded_reason ENUM('replaced', 'matrix_changed') NULL,
  superseded_at DATETIME(6) NULL,
  revoked_by VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  revoked_reason VARCHAR(512) NULL,
  revoked_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_promotion_public (public_id),
  UNIQUE KEY uk_sb_promotion_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_promotion_active (origin_installation_id, matrix_key, active_guard),
  KEY idx_sb_promotion_history (origin_installation_id, matrix_key, created_at, id),
  KEY idx_sb_promotion_backup (backup_public_id, created_at, id),
  KEY idx_sb_promotion_drill (drill_public_id, created_at, id),
  KEY idx_sb_promotion_evidence (drill_evidence_public_id),
  KEY idx_sb_promotion_superseded_by (superseded_by_public_id),
  CONSTRAINT fk_sb_promotion_backup FOREIGN KEY (origin_installation_id, backup_public_id, matrix_key) REFERENCES system_backups(origin_installation_id, public_id, matrix_key) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_promotion_drill FOREIGN KEY (origin_installation_id, drill_public_id, backup_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id, local_source_backup_public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_promotion_evidence FOREIGN KEY (drill_evidence_public_id) REFERENCES system_backup_evidence(public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_promotion_config FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_promotion_superseded_by FOREIGN KEY (superseded_by_public_id) REFERENCES system_backup_promotions(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_promotion_identity CHECK (
    schema_version = 'system-backup-promotion.v1'
    AND public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND backup_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND drill_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND drill_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  ),
  CONSTRAINT chk_sb_promotion_hashes CHECK (
    manifest_checksum REGEXP '^[0-9a-f]{64}$'
    AND acceptance_checksum REGEXP '^[0-9a-f]{64}$'
    AND artifact_registration_hash REGEXP '^[0-9a-f]{64}$'
    AND eligibility_decision_hash REGEXP '^[0-9a-f]{64}$'
    AND drill_evidence_hash REGEXP '^[0-9a-f]{64}$'
    AND creation_health_snapshot_sha256 REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_promotion_registration CHECK (CHAR_LENGTH(artifact_registration_id) BETWEEN 1 AND 128),
  CONSTRAINT chk_sb_promotion_source_versions CHECK (source_backup_row_version >= 1 AND source_drill_row_version >= 1 AND source_prune_guard_version >= 1),
  CONSTRAINT chk_sb_promotion_creation_health CHECK (
    creation_artifact_health = 'healthy'
    AND creation_artifact_access_health = 'healthy'
    AND creation_kek_health = 'healthy'
    AND creation_signature_health = 'healthy'
    AND creation_catalog_health = 'healthy'
    AND creation_evidence_health = 'healthy'
    AND creation_attestation_health = 'healthy'
  ),
  CONSTRAINT chk_sb_promotion_actor CHECK (created_by REGEXP '^[0-9]+$' AND (revoked_by IS NULL OR revoked_by REGEXP '^[0-9]+$')),
  CONSTRAINT chk_sb_promotion_lifecycle CHECK (
    (record_status = 'active' AND superseded_by_public_id IS NULL AND superseded_reason IS NULL AND superseded_at IS NULL AND revoked_by IS NULL AND revoked_reason IS NULL AND revoked_at IS NULL)
    OR (record_status = 'superseded' AND superseded_by_public_id IS NOT NULL AND superseded_by_public_id <> public_id AND superseded_reason IS NOT NULL AND superseded_at IS NOT NULL AND revoked_by IS NULL AND revoked_reason IS NULL AND revoked_at IS NULL)
    OR (record_status = 'revoked' AND superseded_by_public_id IS NULL AND superseded_reason IS NULL AND superseded_at IS NULL AND revoked_by IS NOT NULL AND revoked_reason IS NOT NULL AND OCTET_LENGTH(revoked_reason) BETWEEN 1 AND 512 AND revoked_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_promotion_times CHECK (
    row_version >= 1 AND creation_health_observed_at <= created_at AND updated_at >= created_at
    AND (superseded_at IS NULL OR superseded_at >= created_at)
    AND (revoked_at IS NULL OR revoked_at >= created_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
