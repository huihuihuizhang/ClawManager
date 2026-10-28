CREATE TABLE IF NOT EXISTS system_backup_source_writer_check_states (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-source-writer-check-state.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  registry_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  check_state ENUM('clean', 'drift', 'unknown') NOT NULL,
  reason_code ENUM('none', 'registry_invalid', 'inventory_unavailable', 'permission_denied', 'identity_mismatch', 'writer_missing', 'writer_unregistered', 'policy_mismatch', 'timeout', 'internal') NOT NULL,
  mysql_inventory_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  redis_inventory_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  object_inventory_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  workspace_inventory_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  runtime_inventory_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  difference_count INT UNSIGNED NOT NULL DEFAULT 0,
  evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  checked_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  last_success_at DATETIME(6) NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_writer_check_config (origin_installation_id, config_version),
  KEY idx_sb_writer_check_reconcile (next_reconcile_at, claim_expires_at),
  KEY idx_sb_writer_check_expiry (origin_installation_id, expires_at),
  KEY idx_sb_writer_check_evidence (evidence_public_id),
  CONSTRAINT fk_sb_writer_check_config FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_writer_check_evidence FOREIGN KEY (evidence_public_id) REFERENCES system_backup_evidence(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_writer_check_identity CHECK (
    schema_version = 'system-backup-source-writer-check-state.v1'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND config_version >= 1
    AND CHAR_LENGTH(registry_version) BETWEEN 1 AND 128
  ),
  CONSTRAINT chk_sb_writer_check_hashes CHECK (
    registry_hash REGEXP '^[0-9a-f]{64}$'
    AND mysql_inventory_hash REGEXP '^[0-9a-f]{64}$'
    AND redis_inventory_hash REGEXP '^[0-9a-f]{64}$'
    AND object_inventory_hash REGEXP '^[0-9a-f]{64}$'
    AND workspace_inventory_hash REGEXP '^[0-9a-f]{64}$'
    AND runtime_inventory_hash REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_writer_check_result CHECK (
    (check_state = 'clean' AND reason_code = 'none' AND difference_count = 0 AND last_success_at IS NOT NULL AND last_success_at = checked_at)
    OR (check_state = 'drift' AND reason_code IN ('identity_mismatch', 'writer_missing', 'writer_unregistered', 'policy_mismatch') AND difference_count >= 1)
    OR (check_state = 'unknown' AND reason_code IN ('registry_invalid', 'inventory_unavailable', 'permission_denied', 'timeout', 'internal'))
  ),
  CONSTRAINT chk_sb_writer_check_evidence CHECK (evidence_public_id IS NULL OR evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT chk_sb_writer_check_claim CHECK (
    (claim_owner IS NULL AND claim_expires_at IS NULL)
    OR (claim_owner IS NOT NULL AND CHAR_LENGTH(claim_owner) BETWEEN 1 AND 128 AND claim_expires_at IS NOT NULL AND claim_expires_at > checked_at)
  ),
  CONSTRAINT chk_sb_writer_check_times CHECK (
    expires_at > checked_at
    AND next_reconcile_at >= checked_at
    AND (last_success_at IS NULL OR last_success_at <= checked_at)
    AND row_version >= 1
    AND updated_at >= created_at
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_check_results (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-check-result.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_type ENUM('backup', 'drill', 'preflight', 'artifact_verify', 'catalog_import', 'promotion', 'cleanup', 'prune_run') NOT NULL,
  target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  backup_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'backup' THEN target_public_id ELSE NULL END) STORED,
  drill_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'drill' THEN target_public_id ELSE NULL END) STORED,
  preflight_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'preflight' THEN target_public_id ELSE NULL END) STORED,
  artifact_verify_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'artifact_verify' THEN target_public_id ELSE NULL END) STORED,
  catalog_import_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'catalog_import' THEN target_public_id ELSE NULL END) STORED,
  promotion_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'promotion' THEN target_public_id ELSE NULL END) STORED,
  cleanup_target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'cleanup' THEN target_public_id ELSE NULL END) STORED,
  cleanup_operation_type ENUM('cancel', 'cleanup', 'ownership_resolution', 'provider_proof_register', 'finalization_resolution', 'manual_hold_update', 'config_update', 'promotion_create', 'promotion_revoke', 'catalog_scan', 'catalog_import', 'prune_execute', 'prune_retry', 'artifact_health_reconcile', 'orphan_gc', 'control_metadata_gc', 'evidence_gc') GENERATED ALWAYS AS (CASE WHEN target_type = 'cleanup' THEN 'cleanup' ELSE NULL END) STORED,
  prune_run_target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN target_type = 'prune_run' THEN target_public_id ELSE NULL END) STORED,
  attempt_no INT UNSIGNED NULL,
  attempt_no_sentinel INT UNSIGNED GENERATED ALWAYS AS (COALESCE(attempt_no, 0)) STORED,
  category ENUM('users', 'instances', 'ai_gateway', 'teams', 'resources', 'skill_hub', 'control_plane', 'artifact', 'catalog', 'isolation', 'cleanup', 'prune', 'promotion') NOT NULL,
  mode ENUM('backup_validate', 'restore_validate', 'preflight_diff', 'artifact_health', 'artifact_full', 'catalog_import', 'cleanup_verify', 'prune_verify', 'promotion_validate') NOT NULL,
  check_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status ENUM('passed', 'warning', 'failed', 'skipped') NOT NULL,
  skip_reason ENUM('optional', 'not_applicable') NULL,
  expected_canonical_json BLOB NOT NULL,
  expected_size_bytes INT UNSIGNED NOT NULL,
  expected_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actual_canonical_json BLOB NOT NULL,
  actual_size_bytes INT UNSIGNED NOT NULL,
  actual_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  warning_code VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  check_classification ENUM('validation', 'permission', 'capacity', 'network_timeout', 'rate_limited', 'dependency', 'transient_provider', 'permanent_provider', 'integrity', 'coordination', 'internal') NULL,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  checked_at DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_check_result_identity (target_type, target_public_id, attempt_no_sentinel, mode, category, check_code),
  KEY idx_sb_check_result_target (target_type, target_public_id, checked_at, id),
  KEY idx_sb_check_result_status (origin_installation_id, status, checked_at, id),
  KEY idx_sb_check_result_evidence (evidence_public_id),
  CONSTRAINT fk_sb_check_result_backup FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_drill FOREIGN KEY (origin_installation_id, drill_target_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_preflight FOREIGN KEY (origin_installation_id, preflight_target_public_id) REFERENCES system_backup_preflights(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_artifact_verify FOREIGN KEY (origin_installation_id, artifact_verify_target_public_id) REFERENCES system_backup_artifact_verifications(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_promotion FOREIGN KEY (origin_installation_id, promotion_target_public_id) REFERENCES system_backup_promotions(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_cleanup FOREIGN KEY (origin_installation_id, cleanup_target_public_id, cleanup_operation_type) REFERENCES system_backup_operations(origin_installation_id, public_id, operation_type) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_prune_run FOREIGN KEY (origin_installation_id, prune_run_target_public_id) REFERENCES system_backup_prune_runs(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_check_result_evidence FOREIGN KEY (evidence_public_id) REFERENCES system_backup_evidence(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_check_result_identity CHECK (
    schema_version = 'system-backup-check-result.v1'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND check_code REGEXP '^[a-z0-9][a-z0-9_.-]{0,127}$'
  ),
  CONSTRAINT chk_sb_check_result_target CHECK (
    (target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'backup_validate' AND attempt_no IS NOT NULL AND attempt_no >= 1)
    OR (target_type = 'drill' AND target_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'restore_validate' AND attempt_no IS NOT NULL AND attempt_no >= 1)
    OR (target_type = 'preflight' AND target_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'preflight_diff' AND attempt_no IS NOT NULL AND attempt_no >= 1)
    OR (target_type = 'artifact_verify' AND target_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode IN ('artifact_health', 'artifact_full') AND attempt_no IS NOT NULL AND attempt_no >= 1)
    OR (target_type = 'catalog_import' AND target_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'catalog_import' AND attempt_no IS NULL)
    OR (target_type = 'promotion' AND target_public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'promotion_validate' AND attempt_no IS NULL)
    OR (target_type = 'cleanup' AND target_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'cleanup_verify' AND attempt_no IS NULL)
    OR (target_type = 'prune_run' AND target_public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND mode = 'prune_verify' AND attempt_no IS NULL)
  ),
  CONSTRAINT chk_sb_check_result_category CHECK (
    (mode IN ('backup_validate', 'restore_validate') AND category IN ('users', 'instances', 'ai_gateway', 'teams', 'resources', 'skill_hub', 'control_plane'))
    OR (mode = 'preflight_diff' AND category IN ('users', 'instances', 'ai_gateway', 'teams', 'resources', 'skill_hub', 'control_plane', 'isolation'))
    OR (mode IN ('artifact_health', 'artifact_full') AND category = 'artifact')
    OR (mode = 'catalog_import' AND category IN ('catalog', 'artifact'))
    OR (mode = 'cleanup_verify' AND category = 'cleanup')
    OR (mode = 'prune_verify' AND category = 'prune')
    OR (mode = 'promotion_validate' AND category = 'promotion')
  ),
  CONSTRAINT chk_sb_check_result_payload CHECK (
    expected_size_bytes BETWEEN 2 AND 65535
    AND expected_size_bytes = OCTET_LENGTH(expected_canonical_json)
    AND expected_sha256 = SHA2(expected_canonical_json, 256)
    AND JSON_VALID(CONVERT(expected_canonical_json USING utf8mb4))
    AND JSON_TYPE(CONVERT(expected_canonical_json USING utf8mb4)) = 'OBJECT'
    AND JSON_LENGTH(CONVERT(expected_canonical_json USING utf8mb4)) <= 128
    AND actual_size_bytes BETWEEN 2 AND 65535
    AND actual_size_bytes = OCTET_LENGTH(actual_canonical_json)
    AND actual_sha256 = SHA2(actual_canonical_json, 256)
    AND JSON_VALID(CONVERT(actual_canonical_json USING utf8mb4))
    AND JSON_TYPE(CONVERT(actual_canonical_json USING utf8mb4)) = 'OBJECT'
    AND JSON_LENGTH(CONVERT(actual_canonical_json USING utf8mb4)) <= 128
  ),
  CONSTRAINT chk_sb_check_result_status CHECK (
    (status = 'passed' AND skip_reason IS NULL AND warning_code IS NULL AND check_classification IS NULL AND failure_category = 'none')
    OR (status = 'warning' AND skip_reason IS NULL AND warning_code IS NOT NULL AND warning_code REGEXP '^[a-z0-9][a-z0-9_.-]{0,127}$' AND check_classification IS NULL AND failure_category = 'none')
    OR (status = 'failed' AND skip_reason IS NULL AND warning_code IS NULL AND check_classification IS NOT NULL AND failure_category <> 'none')
    OR (status = 'skipped' AND skip_reason IS NOT NULL AND warning_code IS NULL AND check_classification IS NULL AND failure_category = 'none')
  ),
  CONSTRAINT chk_sb_check_result_evidence CHECK (
    (evidence_public_id IS NULL AND evidence_sha256 IS NULL)
    OR (evidence_public_id IS NOT NULL AND evidence_sha256 IS NOT NULL AND evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND evidence_sha256 REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_check_result_time CHECK (checked_at <= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
