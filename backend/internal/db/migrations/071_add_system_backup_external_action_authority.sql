CREATE TABLE IF NOT EXISTS system_backup_external_actions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-external-action.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_type ENUM('backup', 'prune_item') NOT NULL,
  target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  backup_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'backup' THEN target_public_id ELSE NULL END) STORED,
  prune_item_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'prune_item' THEN target_public_id ELSE NULL END) STORED,
  operation_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  action_type ENUM('manifest_put', 'marker_put', 'acceptance_put', 'catalog_registration_append', 'catalog_tombstone_append') NOT NULL,
  logical_action_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  action_key VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  canonical_payload_bytes MEDIUMBLOB NOT NULL,
  payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  content_length INT UNSIGNED NOT NULL,
  final_key VARCHAR(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  conditional_create_mode ENUM('if_none_match') NOT NULL DEFAULT 'if_none_match',
  conditional_create_value CHAR(1) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '*',
  dispatch_generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
  dispatch_deadline DATETIME(6) NOT NULL,
  state ENUM('request_sent', 'provider_unreachable', 'confirmed_present', 'confirmed_absent', 'conflict') NOT NULL DEFAULT 'request_sent',
  unresolved_backup_guard CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'backup' AND state IN ('request_sent', 'provider_unreachable') THEN target_public_id ELSE NULL END) STORED,
  send_attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
  observe_attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_checked_at DATETIME(6) NULL,
  observed_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  provider_proof_evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  provider_proof_target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN provider_proof_evidence_public_id IS NOT NULL THEN public_id ELSE NULL END) STORED,
  provider_proof_evidence_type ENUM('verifier_report', 'cleanup_result', 'provider_presence_proof', 'provider_absence_proof', 'provider_deletion_receipt', 'ownership_proof', 'capability_snapshot', 'catalog_scan_receipt', 'failure_domain_attestation', 'promotion_release_bundle', 'job_log_chunk', 'diagnostic') GENERATED ALWAYS AS (CASE WHEN provider_proof_evidence_public_id IS NULL THEN NULL WHEN state = 'confirmed_absent' THEN 'provider_absence_proof' ELSE 'provider_presence_proof' END) STORED,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_external_action_public (public_id),
  UNIQUE KEY uk_sb_external_action_identity (target_type, target_public_id, action_type, action_key),
  UNIQUE KEY uk_sb_external_action_unresolved_backup (origin_installation_id, unresolved_backup_guard),
  KEY idx_sb_external_action_target (target_type, target_public_id, created_at, id),
  KEY idx_sb_external_action_state (origin_installation_id, state, dispatch_deadline, id),
  KEY idx_sb_external_action_operation (operation_public_id),
  KEY idx_sb_external_action_evidence (provider_proof_evidence_public_id),
  CONSTRAINT fk_sb_external_action_backup FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_external_action_prune_item FOREIGN KEY (origin_installation_id, prune_item_target_public_id) REFERENCES system_backup_prune_items(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_external_action_operation FOREIGN KEY (operation_public_id) REFERENCES system_backup_operations(public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_external_action_evidence FOREIGN KEY (provider_proof_evidence_public_id, provider_proof_target_public_id, provider_proof_evidence_type) REFERENCES system_backup_evidence(public_id, owner_target_public_id, evidence_type) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_external_action_identity CHECK (
    schema_version = 'system-backup-external-action.v1'
    AND public_id REGEXP '^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND ((target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') OR (target_type = 'prune_item' AND target_public_id REGEXP '^spi_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
    AND (operation_public_id IS NULL OR operation_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_external_action_type CHECK (
    (target_type = 'backup' AND action_type IN ('manifest_put', 'marker_put', 'acceptance_put', 'catalog_registration_append'))
    OR (target_type = 'prune_item' AND action_type = 'catalog_tombstone_append' AND operation_public_id IS NOT NULL)
  ),
  CONSTRAINT chk_sb_external_action_hashes CHECK (
    logical_action_hash REGEXP '^[0-9a-f]{64}$'
    AND payload_sha256 REGEXP '^[0-9a-f]{64}$'
    AND payload_sha256 = SHA2(canonical_payload_bytes, 256)
    AND (observed_checksum IS NULL OR observed_checksum REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_external_action_payload CHECK (
    content_length BETWEEN 1 AND 262144
    AND content_length = OCTET_LENGTH(canonical_payload_bytes)
    AND JSON_VALID(CONVERT(canonical_payload_bytes USING utf8mb4))
  ),
  CONSTRAINT chk_sb_external_action_keys CHECK (
    CHAR_LENGTH(action_key) BETWEEN 1 AND 256
    AND CHAR_LENGTH(final_key) BETWEEN 1 AND 1024
    AND OCTET_LENGTH(final_key) BETWEEN 1 AND 4096
    AND conditional_create_mode = 'if_none_match'
    AND conditional_create_value = '*'
    AND ((action_type = 'manifest_put' AND final_key REGEXP '(^|/)manifest\\.json$') OR (action_type = 'marker_put' AND final_key REGEXP '(^|/)_COMMITTED$') OR (action_type = 'acceptance_put' AND final_key REGEXP '(^|/)_ACCEPTANCE$') OR action_type IN ('catalog_registration_append', 'catalog_tombstone_append'))
  ),
  CONSTRAINT chk_sb_external_action_state CHECK (
    (state = 'request_sent' AND observed_version IS NULL AND observed_checksum IS NULL AND provider_proof_evidence_public_id IS NULL)
    OR (state = 'provider_unreachable' AND last_checked_at IS NOT NULL AND send_attempt_count + observe_attempt_count >= 1 AND observed_version IS NULL AND observed_checksum IS NULL AND provider_proof_evidence_public_id IS NULL)
    OR (state = 'confirmed_present' AND last_checked_at IS NOT NULL AND observe_attempt_count >= 1 AND observed_version IS NOT NULL AND CHAR_LENGTH(observed_version) BETWEEN 1 AND 256 AND observed_checksum = payload_sha256)
    OR (state = 'confirmed_absent' AND last_checked_at IS NOT NULL AND last_checked_at >= dispatch_deadline AND observe_attempt_count >= 1 AND observed_version IS NULL AND observed_checksum IS NULL AND provider_proof_evidence_public_id IS NOT NULL)
    OR (state = 'conflict' AND last_checked_at IS NOT NULL AND observe_attempt_count >= 1 AND observed_version IS NOT NULL AND CHAR_LENGTH(observed_version) BETWEEN 1 AND 256 AND observed_checksum IS NOT NULL AND observed_checksum <> payload_sha256)
  ),
  CONSTRAINT chk_sb_external_action_times CHECK (
    dispatch_generation >= 1 AND row_version >= 1 AND dispatch_deadline > created_at AND updated_at >= created_at
    AND (last_checked_at IS NULL OR last_checked_at >= created_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @sb_backup_external_action_fk_exists = (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_backups'
    AND CONSTRAINT_NAME = 'fk_sb_backup_finalization_action'
    AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sb_backup_external_action_fk_sql = IF(
  @sb_backup_external_action_fk_exists = 0,
  'ALTER TABLE system_backups ADD CONSTRAINT fk_sb_backup_finalization_action FOREIGN KEY (finalization_action_public_id) REFERENCES system_backup_external_actions(public_id) ON DELETE RESTRICT',
  'SELECT 1'
);
PREPARE sb_backup_external_action_fk_stmt FROM @sb_backup_external_action_fk_sql;
EXECUTE sb_backup_external_action_fk_stmt;
DEALLOCATE PREPARE sb_backup_external_action_fk_stmt;

SET @sb_prune_item_external_action_fk_exists = (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_backup_prune_items'
    AND CONSTRAINT_NAME = 'fk_sb_prune_item_external_action'
    AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sb_prune_item_external_action_fk_sql = IF(
  @sb_prune_item_external_action_fk_exists = 0,
  'ALTER TABLE system_backup_prune_items ADD CONSTRAINT fk_sb_prune_item_external_action FOREIGN KEY (external_action_public_id) REFERENCES system_backup_external_actions(public_id) ON DELETE RESTRICT',
  'SELECT 1'
);
PREPARE sb_prune_item_external_action_fk_stmt FROM @sb_prune_item_external_action_fk_sql;
EXECUTE sb_prune_item_external_action_fk_stmt;
DEALLOCATE PREPARE sb_prune_item_external_action_fk_stmt;
