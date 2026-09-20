CREATE TABLE IF NOT EXISTS system_backup_installation_state (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-installation-state.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  active_config_version BIGINT UNSIGNED NOT NULL,
  first_enabled_at DATETIME(6) NULL,
  last_effective_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  last_effective_enabled_transition_at DATETIME(6) NOT NULL,
  monitoring_armed BOOLEAN NOT NULL DEFAULT FALSE,
  monitoring_armed_reason ENUM('none', 'deployment_required', 'previously_enabled') NOT NULL DEFAULT 'none',
  matrix_key ENUM('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node') NOT NULL,
  matrix_transition_operation_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_installation_origin (origin_installation_id),
  CONSTRAINT chk_sb_installation_schema CHECK (schema_version = 'system-backup-installation-state.v1'),
  CONSTRAINT chk_sb_installation_config_version CHECK (active_config_version >= 1),
  CONSTRAINT chk_sb_installation_row_version CHECK (row_version >= 1),
  CONSTRAINT chk_sb_installation_operation_id CHECK (matrix_transition_operation_public_id IS NULL OR matrix_transition_operation_public_id REGEXP '^sop_'),
  CONSTRAINT chk_sb_installation_monitoring CHECK (
    (monitoring_armed = FALSE AND monitoring_armed_reason = 'none' AND first_enabled_at IS NULL)
    OR (monitoring_armed = TRUE AND monitoring_armed_reason = 'deployment_required')
    OR (monitoring_armed = TRUE AND monitoring_armed_reason = 'previously_enabled' AND first_enabled_at IS NOT NULL)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_evidence (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-evidence.v1',
  public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_target_type ENUM('backup', 'backup_staging', 'external_action', 'drill', 'restore_resource', 'preflight', 'artifact_verify', 'catalog_scan', 'catalog_record', 'catalog_import', 'prune_run', 'promotion', 'system') NOT NULL,
  owner_target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_type ENUM('verifier_report', 'cleanup_result', 'provider_presence_proof', 'provider_absence_proof', 'provider_deletion_receipt', 'ownership_proof', 'capability_snapshot', 'catalog_scan_receipt', 'failure_domain_attestation', 'promotion_release_bundle', 'job_log_chunk', 'diagnostic') NOT NULL,
  storage_state ENUM('inline', 'pending', 'write_unknown', 'write_failed', 'ready', 'deleting', 'delete_failed', 'deleted') NOT NULL,
  evidence_failure_code ENUM('none', 'redaction_failed', 'capacity_exceeded', 'provider_unavailable', 'permission_denied', 'checksum_mismatch', 'encryption_key_unavailable', 'deadline_exceeded', 'internal') NOT NULL DEFAULT 'none',
  storage_provider_role ENUM('evidence') NULL,
  storage_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  storage_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  storage_relative_key VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NULL,
  storage_relative_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  storage_immutable_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  inline_payload VARBINARY(8192) NULL,
  content_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  content_size_bytes BIGINT UNSIGNED NOT NULL,
  object_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  object_size_bytes BIGINT UNSIGNED NULL,
  plaintext_chunk_size_bytes INT UNSIGNED NULL,
  chunk_count INT UNSIGNED NOT NULL DEFAULT 0,
  chunk_list_root CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  media_type ENUM('application/json', 'application/jose', 'application/cbor', 'text/plain') NOT NULL,
  encryption ENUM('none', 'envelope_v1') NOT NULL,
  envelope_framing_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  kek_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  kek_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  envelope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  redaction_classification ENUM('public', 'internal', 'confidential', 'sensitive') NOT NULL,
  observed_health ENUM('healthy', 'degraded', 'unknown') NOT NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  last_checked_at DATETIME(6) NULL,
  expires_at DATETIME(6) NOT NULL,
  protected_until DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_evidence_public_id (public_id),
  UNIQUE KEY uk_sb_evidence_public_owner_type (public_id, owner_target_public_id, evidence_type),
  KEY idx_sb_evidence_owner (owner_target_type, owner_target_public_id),
  KEY idx_sb_evidence_reconcile (storage_state, next_reconcile_at),
  KEY idx_sb_evidence_expiry (expires_at, protected_until),
  CONSTRAINT chk_sb_evidence_schema CHECK (schema_version = 'system-backup-evidence.v1'),
  CONSTRAINT chk_sb_evidence_public_id CHECK (public_id REGEXP '^sev_'),
  CONSTRAINT chk_sb_evidence_owner_id CHECK (
    (owner_target_type = 'backup' AND owner_target_public_id REGEXP '^sbk_')
    OR (owner_target_type = 'backup_staging' AND owner_target_public_id REGEXP '^sbs_')
    OR (owner_target_type = 'external_action' AND owner_target_public_id REGEXP '^sxa_')
    OR (owner_target_type = 'drill' AND owner_target_public_id REGEXP '^sdr_')
    OR (owner_target_type = 'restore_resource' AND owner_target_public_id REGEXP '^srr_')
    OR (owner_target_type = 'preflight' AND owner_target_public_id REGEXP '^spf_')
    OR (owner_target_type = 'artifact_verify' AND owner_target_public_id REGEXP '^sav_')
    OR (owner_target_type = 'catalog_scan' AND owner_target_public_id REGEXP '^scs_')
    OR (owner_target_type = 'catalog_record' AND owner_target_public_id REGEXP '^scr_')
    OR (owner_target_type = 'catalog_import' AND owner_target_public_id REGEXP '^sci_')
    OR (owner_target_type = 'prune_run' AND owner_target_public_id REGEXP '^spr_')
    OR (owner_target_type = 'promotion' AND owner_target_public_id REGEXP '^spm_')
    OR (owner_target_type = 'system' AND owner_target_public_id REGEXP '^installation_')
  ),
  CONSTRAINT chk_sb_evidence_failure CHECK (
    (storage_state IN ('inline', 'pending', 'ready', 'deleting', 'deleted') AND evidence_failure_code = 'none')
    OR (storage_state = 'write_unknown' AND evidence_failure_code IN ('provider_unavailable', 'deadline_exceeded'))
    OR (storage_state = 'write_failed' AND evidence_failure_code <> 'none')
    OR (storage_state = 'delete_failed' AND evidence_failure_code IN ('provider_unavailable', 'permission_denied', 'checksum_mismatch', 'deadline_exceeded', 'internal'))
  ),
  CONSTRAINT chk_sb_evidence_storage CHECK (
    (storage_state = 'inline'
      AND storage_provider_role IS NULL AND storage_identity_hash IS NULL AND storage_ref_version IS NULL
      AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL AND storage_immutable_version IS NULL
      AND inline_payload IS NOT NULL AND object_checksum IS NULL AND object_size_bytes IS NULL
      AND plaintext_chunk_size_bytes IS NULL AND chunk_count = 0 AND chunk_list_root IS NULL)
    OR (storage_state <> 'inline'
      AND storage_provider_role = 'evidence' AND storage_identity_hash IS NOT NULL AND storage_ref_version IS NOT NULL
      AND storage_relative_key IS NOT NULL AND storage_relative_key_hash IS NOT NULL AND inline_payload IS NULL)
  ),
  CONSTRAINT chk_sb_evidence_relative_key CHECK (storage_relative_key IS NULL OR (storage_relative_key REGEXP '^[A-Za-z0-9._/-]+$' AND storage_relative_key NOT REGEXP '(^|/)\\.\\.?(/|$)')),
  CONSTRAINT chk_sb_evidence_ready_object CHECK (
    storage_state NOT IN ('ready', 'deleting', 'delete_failed', 'deleted')
    OR (storage_immutable_version IS NOT NULL AND object_checksum IS NOT NULL AND object_size_bytes IS NOT NULL
      AND plaintext_chunk_size_bytes = 1048576 AND chunk_count >= 1 AND chunk_list_root IS NOT NULL)
  ),
  CONSTRAINT chk_sb_evidence_encryption CHECK (
    (encryption = 'none' AND envelope_framing_version IS NULL AND kek_identity_hash IS NULL AND kek_version IS NULL AND envelope_hash IS NULL)
    OR (encryption = 'envelope_v1' AND envelope_framing_version = 'system-backup-evidence-envelope.v1'
      AND kek_identity_hash IS NOT NULL AND kek_version IS NOT NULL AND envelope_hash IS NOT NULL)
  ),
  CONSTRAINT chk_sb_evidence_classification CHECK (redaction_classification NOT IN ('confidential', 'sensitive') OR encryption = 'envelope_v1'),
  CONSTRAINT chk_sb_evidence_claim CHECK ((claim_owner IS NULL AND claim_expires_at IS NULL) OR (claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_evidence_content_size CHECK (content_size_bytes <= 1073741824),
  CONSTRAINT chk_sb_evidence_hashes CHECK (
    content_checksum REGEXP '^[0-9a-f]{64}$'
    AND (storage_identity_hash IS NULL OR storage_identity_hash REGEXP '^[0-9a-f]{64}$')
    AND (storage_relative_key_hash IS NULL OR storage_relative_key_hash REGEXP '^[0-9a-f]{64}$')
    AND (object_checksum IS NULL OR object_checksum REGEXP '^[0-9a-f]{64}$')
    AND (chunk_list_root IS NULL OR chunk_list_root REGEXP '^[0-9a-f]{64}$')
    AND (kek_identity_hash IS NULL OR kek_identity_hash REGEXP '^[0-9a-f]{64}$')
    AND (envelope_hash IS NULL OR envelope_hash REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_evidence_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_evidence_chunks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  evidence_id BIGINT UNSIGNED NOT NULL,
  chunk_index INT UNSIGNED NOT NULL,
  plaintext_offset BIGINT UNSIGNED NOT NULL,
  plaintext_length INT UNSIGNED NOT NULL,
  plaintext_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  object_frame_offset BIGINT UNSIGNED NOT NULL,
  object_frame_length BIGINT UNSIGNED NOT NULL,
  ciphertext_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gcm_nonce VARBINARY(64) NOT NULL,
  gcm_tag VARBINARY(64) NOT NULL,
  UNIQUE KEY uk_sb_evidence_chunk (evidence_id, chunk_index),
  CONSTRAINT fk_sb_evidence_chunk_evidence FOREIGN KEY (evidence_id) REFERENCES system_backup_evidence(id) ON DELETE CASCADE,
  CONSTRAINT chk_sb_evidence_chunk_length CHECK (plaintext_length BETWEEN 1 AND 1048576),
  CONSTRAINT chk_sb_evidence_chunk_frame CHECK (object_frame_length >= 1),
  CONSTRAINT chk_sb_evidence_chunk_hashes CHECK (plaintext_sha256 REGEXP '^[0-9a-f]{64}$' AND ciphertext_sha256 REGEXP '^[0-9a-f]{64}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_log_chunks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-log-chunk.v1',
  task_type ENUM('backup', 'drill', 'preflight', 'artifact_verify') NOT NULL,
  task_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_number INT UNSIGNED NOT NULL,
  phase ENUM('capture', 'secret_capture', 'publish', 'restore', 'normalize', 'verify', 'preflight') NOT NULL,
  job_uid VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_generation INT UNSIGNED NOT NULL,
  chunk_sequence BIGINT UNSIGNED NOT NULL,
  first_log_at DATETIME(6) NULL,
  last_log_at DATETIME(6) NULL,
  line_count INT UNSIGNED NOT NULL DEFAULT 0,
  redacted_evidence_id BIGINT UNSIGNED NULL,
  redacted_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  ingest_status ENUM('pending', 'ready', 'failed') NOT NULL,
  log_ingest_failure_code ENUM('none', 'source_unavailable', 'redaction_failed', 'evidence_write_failed', 'sequence_conflict', 'capacity_exceeded', 'internal') NOT NULL DEFAULT 'none',
  available_until DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_log_chunk (task_type, task_public_id, job_uid, job_generation, chunk_sequence),
  KEY idx_sb_log_available (available_until),
  CONSTRAINT fk_sb_log_evidence FOREIGN KEY (redacted_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_log_schema CHECK (schema_version = 'system-backup-log-chunk.v1'),
  CONSTRAINT chk_sb_log_task_id CHECK (
    (task_type = 'backup' AND task_public_id REGEXP '^sbk_')
    OR (task_type = 'drill' AND task_public_id REGEXP '^sdr_')
    OR (task_type = 'preflight' AND task_public_id REGEXP '^spf_')
    OR (task_type = 'artifact_verify' AND task_public_id REGEXP '^sav_')
  ),
  CONSTRAINT chk_sb_log_attempt CHECK (attempt_number >= 1 AND job_generation >= 1),
  CONSTRAINT chk_sb_log_failure CHECK (
    (ingest_status IN ('pending', 'ready') AND log_ingest_failure_code = 'none')
    OR (ingest_status = 'failed' AND log_ingest_failure_code <> 'none')
  ),
  CONSTRAINT chk_sb_log_payload CHECK (
    (ingest_status = 'pending' AND first_log_at IS NULL AND last_log_at IS NULL AND line_count = 0 AND redacted_evidence_id IS NULL AND redacted_evidence_sha256 IS NULL)
    OR (ingest_status = 'ready' AND first_log_at IS NOT NULL AND last_log_at IS NOT NULL AND line_count BETWEEN 1 AND 1000 AND redacted_evidence_id IS NOT NULL AND redacted_evidence_sha256 IS NOT NULL)
    OR ingest_status = 'failed'
  ),
  CONSTRAINT chk_sb_log_evidence_pair CHECK ((redacted_evidence_id IS NULL AND redacted_evidence_sha256 IS NULL) OR (redacted_evidence_id IS NOT NULL AND redacted_evidence_sha256 REGEXP '^[0-9a-f]{64}$')),
  CONSTRAINT chk_sb_log_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_dependency_health (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-dependency-health.v1',
  dependency_kind ENUM('artifact_credential', 'ca', 'kek', 'signing', 'catalog', 'evidence', 'attestation') NOT NULL,
  identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  identity_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_target_type ENUM('backup', 'catalog_import', 'promotion', 'system') NOT NULL,
  owner_target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observed_health ENUM('healthy', 'degraded', 'unknown') NOT NULL,
  health_reason ENUM('none', 'provider_unavailable', 'credential_unavailable', 'ca_unavailable', 'kek_unavailable', 'signing_key_unavailable', 'signature_invalid', 'key_compromised', 'acceptance_invalid', 'catalog_unavailable', 'evidence_unavailable', 'attestation_invalid', 'attestation_expired', 'artifact_corrupt', 'catalog_tombstoned', 'delete_failed', 'cleanup_residual_data', 'finalization_pending', 'verification_inconclusive') NOT NULL,
  observed_immutable_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  checked_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  protected_until DATETIME(6) NULL,
  evidence_id BIGINT UNSIGNED NULL,
  evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_dependency_identity (dependency_kind, identity_hash, identity_version, owner_target_type, owner_target_public_id),
  KEY idx_sb_dependency_expiry (expires_at, protected_until),
  CONSTRAINT fk_sb_dependency_evidence FOREIGN KEY (evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_dependency_schema CHECK (schema_version = 'system-backup-dependency-health.v1'),
  CONSTRAINT chk_sb_dependency_owner CHECK (
    (owner_target_type = 'backup' AND owner_target_public_id REGEXP '^sbk_')
    OR (owner_target_type = 'catalog_import' AND owner_target_public_id REGEXP '^sci_')
    OR (owner_target_type = 'promotion' AND owner_target_public_id REGEXP '^spm_')
    OR (owner_target_type = 'system' AND owner_target_public_id REGEXP '^installation_')
  ),
  CONSTRAINT chk_sb_dependency_health CHECK ((observed_health = 'healthy' AND health_reason = 'none') OR (observed_health <> 'healthy' AND health_reason <> 'none')),
  CONSTRAINT chk_sb_dependency_observed CHECK ((observed_immutable_version IS NULL AND observed_checksum IS NULL) OR (observed_immutable_version IS NOT NULL AND observed_checksum REGEXP '^[0-9a-f]{64}$')),
  CONSTRAINT chk_sb_dependency_evidence CHECK ((evidence_id IS NULL AND evidence_sha256 IS NULL) OR (evidence_id IS NOT NULL AND evidence_sha256 REGEXP '^[0-9a-f]{64}$')),
  CONSTRAINT chk_sb_dependency_time CHECK (expires_at > checked_at),
  CONSTRAINT chk_sb_dependency_identity_hash CHECK (identity_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_dependency_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_provider_capabilities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-provider-capability.v1',
  provider_role ENUM('artifact', 'catalog', 'evidence') NOT NULL,
  provider_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  provider_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  capability_code ENUM('conditional_create', 'checksum_bound_request', 'scoped_upload_credential', 'scoped_read_credential', 'scoped_delete_credential', 'multipart_resume', 'object_checksum', 'version_listing', 'delete_marker_listing', 'strong_read_after_write', 'tls_verified', 'scoped_append_credential', 'provider_snapshot_listing', 'inventory_manifest_listing', 'versioned_absence_proof', 'scoped_write_credential') NOT NULL,
  status ENUM('supported', 'degraded', 'unsupported') NOT NULL,
  capability_reason_code ENUM('none', 'probe_failed', 'provider_unavailable', 'credential_unavailable', 'permission_denied', 'unsupported_api', 'response_invalid', 'version_drift', 'internal') NOT NULL,
  observed_provider_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  checked_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  evidence_id BIGINT UNSIGNED NULL,
  evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_provider_capability (provider_role, provider_identity_hash, provider_ref_version, capability_code),
  KEY idx_sb_provider_reconcile (next_reconcile_at, claim_expires_at),
  KEY idx_sb_provider_expiry (expires_at),
  CONSTRAINT fk_sb_provider_evidence FOREIGN KEY (evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_provider_schema CHECK (schema_version = 'system-backup-provider-capability.v1'),
  CONSTRAINT chk_sb_provider_status CHECK ((status = 'supported' AND capability_reason_code = 'none') OR (status <> 'supported' AND capability_reason_code <> 'none')),
  CONSTRAINT chk_sb_provider_claim CHECK ((claim_owner IS NULL AND claim_expires_at IS NULL) OR (claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_provider_evidence CHECK ((evidence_id IS NULL AND evidence_sha256 IS NULL) OR (evidence_id IS NOT NULL AND evidence_sha256 REGEXP '^[0-9a-f]{64}$')),
  CONSTRAINT chk_sb_provider_time CHECK (expires_at > checked_at),
  CONSTRAINT chk_sb_provider_identity_hash CHECK (provider_identity_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_provider_role_code CHECK (
    (provider_role = 'artifact' AND capability_code IN ('conditional_create', 'checksum_bound_request', 'scoped_upload_credential', 'scoped_read_credential', 'scoped_delete_credential', 'multipart_resume', 'object_checksum', 'version_listing', 'delete_marker_listing', 'strong_read_after_write', 'tls_verified'))
    OR (provider_role = 'catalog' AND capability_code IN ('conditional_create', 'checksum_bound_request', 'scoped_read_credential', 'scoped_append_credential', 'strong_read_after_write', 'provider_snapshot_listing', 'inventory_manifest_listing', 'versioned_absence_proof', 'tls_verified'))
    OR (provider_role = 'evidence' AND capability_code IN ('conditional_create', 'checksum_bound_request', 'scoped_read_credential', 'scoped_write_credential', 'scoped_delete_credential', 'object_checksum', 'strong_read_after_write', 'versioned_absence_proof', 'tls_verified'))
  ),
  CONSTRAINT chk_sb_provider_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_compact_tombstones (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-compact-tombstone.v1',
  source_type ENUM('backup', 'drill', 'preflight', 'artifact_verify', 'catalog_import', 'prune_run', 'operation', 'promotion') NOT NULL,
  source_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  terminal_status ENUM('succeeded', 'failed', 'canceled', 'expired', 'partial_failed', 'revoked', 'superseded') NOT NULL,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL,
  eligibility BOOLEAN NULL,
  artifact_final_state ENUM('committed', 'delete_failed', 'deleted', 'corrupt') NULL,
  response_summary_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_created_at DATETIME(6) NOT NULL,
  source_finished_at DATETIME(6) NOT NULL,
  detail_rolling_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gc_batch_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gc_at DATETIME(6) NOT NULL,
  retention_class ENUM('destructive_permanent', 'standard') NOT NULL,
  delete_after DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  UNIQUE KEY uk_sb_tombstone_source (origin_installation_id, source_type, source_public_id),
  UNIQUE KEY uk_sb_tombstone_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_tombstone_delete_after (retention_class, delete_after),
  CONSTRAINT chk_sb_tombstone_schema CHECK (schema_version = 'system-backup-compact-tombstone.v1'),
  CONSTRAINT chk_sb_tombstone_source_id CHECK (
    (source_type = 'backup' AND source_public_id REGEXP '^sbk_')
    OR (source_type = 'drill' AND source_public_id REGEXP '^sdr_')
    OR (source_type = 'preflight' AND source_public_id REGEXP '^spf_')
    OR (source_type = 'artifact_verify' AND source_public_id REGEXP '^sav_')
    OR (source_type = 'catalog_import' AND source_public_id REGEXP '^sci_')
    OR (source_type = 'prune_run' AND source_public_id REGEXP '^spr_')
    OR (source_type = 'operation' AND source_public_id REGEXP '^sop_')
    OR (source_type = 'promotion' AND source_public_id REGEXP '^spm_')
  ),
  CONSTRAINT chk_sb_tombstone_retention CHECK (
    (retention_class = 'destructive_permanent' AND delete_after IS NULL)
    OR (retention_class = 'standard' AND delete_after IS NOT NULL AND delete_after > gc_at)
  ),
  CONSTRAINT chk_sb_tombstone_time CHECK (source_finished_at >= source_created_at AND gc_at >= source_finished_at),
  CONSTRAINT chk_sb_tombstone_hashes CHECK (request_hash REGEXP '^[0-9a-f]{64}$' AND response_summary_hash REGEXP '^[0-9a-f]{64}$' AND detail_rolling_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_tombstone_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
