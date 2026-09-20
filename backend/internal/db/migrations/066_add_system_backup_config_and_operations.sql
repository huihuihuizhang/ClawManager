CREATE TABLE IF NOT EXISTS system_backup_configs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-config.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  version BIGINT UNSIGNED NOT NULL,
  copied_from_version BIGINT UNSIGNED NULL,
  config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_size_bytes INT UNSIGNED NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  alert_profile ENUM('production', 'development') NOT NULL DEFAULT 'production',
  minimum_recovery_points INT UNSIGNED NOT NULL DEFAULT 1,

  controller_claim_ttl_seconds INT UNSIGNED NOT NULL,
  controller_claim_heartbeat_seconds INT UNSIGNED NOT NULL,
  controller_reconcile_interval_seconds INT UNSIGNED NOT NULL,
  mutation_lease_ttl_seconds INT UNSIGNED NOT NULL,
  mutation_lease_heartbeat_seconds INT UNSIGNED NOT NULL,
  artifact_lease_ttl_seconds INT UNSIGNED NOT NULL,
  artifact_lease_heartbeat_seconds INT UNSIGNED NOT NULL,
  gate_acquisition_timeout_seconds INT UNSIGNED NOT NULL,
  quiesce_max_hold_seconds INT UNSIGNED NOT NULL,
  maintenance_lock_ttl_seconds INT UNSIGNED NOT NULL,
  watchdog_db_unavailable_grace_seconds INT UNSIGNED NOT NULL,
  watchdog_safety_margin_seconds INT UNSIGNED NOT NULL,
  staging_retention_seconds INT UNSIGNED NOT NULL,
  retention_seconds INT UNSIGNED NOT NULL,
  prune_candidate_ttl_seconds INT UNSIGNED NOT NULL,
  confirmation_ttl_seconds INT UNSIGNED NOT NULL,
  logs_retention_seconds INT UNSIGNED NOT NULL,
  evidence_retention_seconds INT UNSIGNED NOT NULL,
  promotion_health_max_age_seconds INT UNSIGNED NOT NULL,
  task_cancel_deadline_seconds INT UNSIGNED NOT NULL,
  cleanup_deadline_seconds INT UNSIGNED NOT NULL,
  retry_initial_backoff_seconds INT UNSIGNED NOT NULL,
  retry_max_backoff_seconds INT UNSIGNED NOT NULL,
  orphan_safety_window_seconds INT UNSIGNED NOT NULL,
  artifact_health_interval_seconds INT UNSIGNED NOT NULL,
  catalog_scan_interval_seconds INT UNSIGNED NOT NULL,
  catalog_scan_deadline_seconds INT UNSIGNED NOT NULL,
  provider_consistency_window_seconds INT UNSIGNED NOT NULL,
  redis_clock_skew_seconds INT UNSIGNED NOT NULL,
  strong_auth_max_age_seconds INT UNSIGNED NOT NULL,
  strong_auth_clock_skew_seconds INT UNSIGNED NOT NULL,
  provider_proof_max_age_seconds INT UNSIGNED NOT NULL,
  capture_certificate_ttl_seconds INT UNSIGNED NOT NULL,
  finalization_resolution_grace_seconds INT UNSIGNED NOT NULL,
  recovery_point_objective_seconds INT UNSIGNED NOT NULL,
  first_enable_recovery_alert_grace_seconds INT UNSIGNED NOT NULL,
  control_metadata_retention_seconds INT UNSIGNED NOT NULL,
  backup_task_deadline_seconds INT UNSIGNED NOT NULL,
  drill_task_deadline_seconds INT UNSIGNED NOT NULL,
  preflight_task_deadline_seconds INT UNSIGNED NOT NULL,
  artifact_verify_task_deadline_seconds INT UNSIGNED NOT NULL,
  operation_deadline_seconds INT UNSIGNED NOT NULL,
  finalization_resolution_deadline_seconds INT UNSIGNED NOT NULL,
  prune_operation_deadline_seconds INT UNSIGNED NOT NULL,

  control_metadata_capacity_bytes BIGINT UNSIGNED NOT NULL,
  staging_capacity_bytes BIGINT UNSIGNED NOT NULL,
  max_artifact_bytes BIGINT UNSIGNED NOT NULL,
  max_index_bytes BIGINT UNSIGNED NOT NULL,
  max_plaintext_buffer_bytes BIGINT UNSIGNED NOT NULL,
  max_source_items INT UNSIGNED NOT NULL,
  minimum_capture_throughput_bytes_per_second INT UNSIGNED NOT NULL,
  source_size_safety_factor DECIMAL(4,2) UNSIGNED NOT NULL,
  max_log_bytes BIGINT UNSIGNED NOT NULL,
  max_log_lines INT UNSIGNED NOT NULL,
  log_chunk_bytes INT UNSIGNED NOT NULL,
  log_chunk_lines INT UNSIGNED NOT NULL,

  max_concurrent_drills INT UNSIGNED NOT NULL,
  max_concurrent_preflights INT UNSIGNED NOT NULL,
  max_concurrent_artifact_verifications INT UNSIGNED NOT NULL,
  max_pending_tasks INT UNSIGNED NOT NULL,
  max_auto_attempts INT UNSIGNED NOT NULL,
  preflight_query_timeout_seconds INT UNSIGNED NOT NULL,
  preflight_provider_qps INT UNSIGNED NOT NULL,
  preflight_max_scan_bytes BIGINT UNSIGNED NOT NULL,
  preflight_max_scan_items INT UNSIGNED NOT NULL,

  parts_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  parts_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  redis_sources_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  redis_sources_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  failure_domains_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  failure_domains_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  disaster_identity_mapping_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  disaster_identity_mapping_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_writers_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_writers_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  rbac_bindings_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  rbac_bindings_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  secret_allowlist_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  secret_allowlist_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  strong_auth_issuers_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  strong_auth_issuers_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  provider_proof_issuers_registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  provider_proof_issuers_registry_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

  artifact_write_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_write_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_read_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_read_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_delete_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_delete_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_upload_issuer_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_upload_issuer_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_ca_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_ca_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_store_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_store_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_write_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_write_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_read_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_read_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_delete_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_delete_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_ca_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_ca_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_kek_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_kek_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  kek_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  kek_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  capture_signing_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  capture_signing_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  acceptance_signing_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  acceptance_signing_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_signing_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_signing_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_read_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_read_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_append_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_append_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_snapshot_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_snapshot_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  nonce_hmac_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  nonce_hmac_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status_relay_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status_relay_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

  created_by VARCHAR(128) NOT NULL,
  change_reason VARCHAR(512) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_config_version (origin_installation_id, version),
  UNIQUE KEY uk_sb_config_snapshot (origin_installation_id, version, config_sha256, config_size_bytes),
  KEY idx_sb_config_created (origin_installation_id, created_at, id),
  CONSTRAINT fk_sb_config_copied_from FOREIGN KEY (origin_installation_id, copied_from_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_config_schema CHECK (schema_version = 'system-backup-config.v1'),
  CONSTRAINT chk_sb_config_origin CHECK (origin_installation_id REGEXP '^installation_'),
  CONSTRAINT chk_sb_config_version CHECK (version >= 1 AND (copied_from_version IS NULL OR copied_from_version < version)),
  CONSTRAINT chk_sb_config_hash_size CHECK (config_sha256 REGEXP '^[0-9a-f]{64}$' AND config_size_bytes BETWEEN 2 AND 262144),
  CONSTRAINT chk_sb_config_base CHECK (minimum_recovery_points BETWEEN 1 AND 100 AND row_version = 1),
  CONSTRAINT chk_sb_config_durations_1 CHECK (
    controller_claim_ttl_seconds BETWEEN 15 AND 300
    AND controller_claim_heartbeat_seconds BETWEEN 5 AND 100
    AND controller_reconcile_interval_seconds BETWEEN 1 AND 60
    AND mutation_lease_ttl_seconds BETWEEN 6 AND 120
    AND mutation_lease_heartbeat_seconds BETWEEN 2 AND 40
    AND artifact_lease_ttl_seconds BETWEEN 15 AND 300
    AND artifact_lease_heartbeat_seconds BETWEEN 5 AND 100
    AND gate_acquisition_timeout_seconds BETWEEN 10 AND 600
    AND quiesce_max_hold_seconds BETWEEN 30 AND 3600
    AND maintenance_lock_ttl_seconds BETWEEN 65 AND 7200
    AND watchdog_db_unavailable_grace_seconds BETWEEN 5 AND 60
    AND watchdog_safety_margin_seconds BETWEEN 5 AND 60
    AND staging_retention_seconds BETWEEN 3600 AND 604800
    AND retention_seconds BETWEEN 86400 AND 31536000
    AND prune_candidate_ttl_seconds BETWEEN 3600 AND 604800
    AND confirmation_ttl_seconds BETWEEN 60 AND 3600
    AND logs_retention_seconds BETWEEN 3600 AND 2592000
    AND evidence_retention_seconds BETWEEN 86400 AND 31536000
    AND promotion_health_max_age_seconds BETWEEN 60 AND 86400
    AND task_cancel_deadline_seconds BETWEEN 10 AND 1800
    AND cleanup_deadline_seconds BETWEEN 60 AND 21600
  ),
  CONSTRAINT chk_sb_config_durations_2 CHECK (
    retry_initial_backoff_seconds BETWEEN 1 AND 60
    AND retry_max_backoff_seconds BETWEEN 5 AND 600
    AND orphan_safety_window_seconds BETWEEN 300 AND 86400
    AND artifact_health_interval_seconds BETWEEN 300 AND 86400
    AND catalog_scan_interval_seconds BETWEEN 300 AND 86400
    AND catalog_scan_deadline_seconds BETWEEN 60 AND 21600
    AND provider_consistency_window_seconds BETWEEN 1 AND 600
    AND redis_clock_skew_seconds <= 60
    AND strong_auth_max_age_seconds BETWEEN 60 AND 900
    AND strong_auth_clock_skew_seconds <= 120
    AND provider_proof_max_age_seconds BETWEEN 60 AND 3600
    AND capture_certificate_ttl_seconds BETWEEN 3600 AND 86400
    AND finalization_resolution_grace_seconds BETWEEN 60 AND 3600
    AND recovery_point_objective_seconds BETWEEN 3600 AND 2592000
    AND first_enable_recovery_alert_grace_seconds <= 604800
    AND control_metadata_retention_seconds BETWEEN 2592000 AND 157680000
    AND backup_task_deadline_seconds BETWEEN 600 AND 43200
    AND drill_task_deadline_seconds BETWEEN 600 AND 43200
    AND preflight_task_deadline_seconds BETWEEN 60 AND 7200
    AND artifact_verify_task_deadline_seconds BETWEEN 300 AND 21600
    AND operation_deadline_seconds BETWEEN 60 AND 86400
    AND finalization_resolution_deadline_seconds BETWEEN 60 AND 86400
    AND prune_operation_deadline_seconds BETWEEN 60 AND 86400
  ),
  CONSTRAINT chk_sb_config_capacity CHECK (
    control_metadata_capacity_bytes BETWEEN 1073741824 AND 1099511627776
    AND staging_capacity_bytes BETWEEN 1073741824 AND 1099511627776
    AND max_artifact_bytes BETWEEN 1048576 AND 966367641600
    AND max_index_bytes BETWEEN 1048576 AND 8589934592
    AND max_plaintext_buffer_bytes BETWEEN 1048576 AND 268435456
    AND max_source_items BETWEEN 1 AND 100000000
    AND minimum_capture_throughput_bytes_per_second BETWEEN 1048576 AND 1073741824
    AND source_size_safety_factor BETWEEN 1.00 AND 2.00
    AND max_log_bytes BETWEEN 1048576 AND 1073741824
    AND max_log_lines BETWEEN 1000 AND 1000000
    AND log_chunk_bytes BETWEEN 4096 AND 1048576
    AND log_chunk_lines BETWEEN 1 AND 1000
  ),
  CONSTRAINT chk_sb_config_concurrency CHECK (
    max_concurrent_drills BETWEEN 1 AND 10
    AND max_concurrent_preflights BETWEEN 1 AND 20
    AND max_concurrent_artifact_verifications BETWEEN 1 AND 10
    AND max_pending_tasks BETWEEN 1 AND 1000
    AND max_auto_attempts BETWEEN 1 AND 10
  ),
  CONSTRAINT chk_sb_config_preflight CHECK (
    preflight_query_timeout_seconds BETWEEN 5 AND 300
    AND preflight_provider_qps BETWEEN 1 AND 200
    AND preflight_max_scan_bytes BETWEEN 1073741824 AND 107374182400
    AND preflight_max_scan_items BETWEEN 1000 AND 10000000
  ),
  CONSTRAINT chk_sb_config_relationships CHECK (
    controller_claim_heartbeat_seconds * 3 <= controller_claim_ttl_seconds
    AND mutation_lease_heartbeat_seconds * 3 <= mutation_lease_ttl_seconds
    AND artifact_lease_heartbeat_seconds * 3 <= artifact_lease_ttl_seconds
    AND maintenance_lock_ttl_seconds >= quiesce_max_hold_seconds + watchdog_safety_margin_seconds + controller_claim_ttl_seconds * 2
    AND retry_max_backoff_seconds >= retry_initial_backoff_seconds
    AND evidence_retention_seconds >= retention_seconds
    AND control_metadata_retention_seconds >= retention_seconds
    AND control_metadata_retention_seconds >= evidence_retention_seconds
    AND control_metadata_retention_seconds >= logs_retention_seconds
    AND staging_capacity_bytes * 10 >= max_artifact_bytes * 11 + max_index_bytes * 10
    AND log_chunk_bytes <= max_log_bytes
    AND log_chunk_lines <= max_log_lines
    AND capture_certificate_ttl_seconds > backup_task_deadline_seconds
  ),
  CONSTRAINT chk_sb_config_registry_hashes CHECK (
    parts_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND redis_sources_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND failure_domains_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND disaster_identity_mapping_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND source_writers_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND rbac_bindings_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND secret_allowlist_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND strong_auth_issuers_registry_sha256 REGEXP '^[0-9a-f]{64}$'
    AND provider_proof_issuers_registry_sha256 REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_config_registry_versions CHECK (
    CHAR_LENGTH(parts_registry_version) >= 1
    AND CHAR_LENGTH(redis_sources_registry_version) >= 1
    AND CHAR_LENGTH(failure_domains_registry_version) >= 1
    AND CHAR_LENGTH(disaster_identity_mapping_registry_version) >= 1
    AND CHAR_LENGTH(source_writers_registry_version) >= 1
    AND CHAR_LENGTH(rbac_bindings_registry_version) >= 1
    AND CHAR_LENGTH(secret_allowlist_registry_version) >= 1
    AND CHAR_LENGTH(strong_auth_issuers_registry_version) >= 1
    AND CHAR_LENGTH(provider_proof_issuers_registry_version) >= 1
  ),
  CONSTRAINT chk_sb_config_reference_hashes CHECK (
    artifact_write_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND artifact_read_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND artifact_delete_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND artifact_upload_issuer_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND artifact_ca_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_store_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_write_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_read_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_delete_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_ca_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND evidence_kek_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND kek_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND capture_signing_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND acceptance_signing_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND catalog_signing_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND catalog_read_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND catalog_append_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND catalog_snapshot_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND nonce_hmac_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND status_relay_identity_hash REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_config_reference_versions CHECK (
    CHAR_LENGTH(artifact_write_ref_version) >= 1
    AND CHAR_LENGTH(artifact_read_ref_version) >= 1
    AND CHAR_LENGTH(artifact_delete_ref_version) >= 1
    AND CHAR_LENGTH(artifact_upload_issuer_ref_version) >= 1
    AND CHAR_LENGTH(artifact_ca_ref_version) >= 1
    AND CHAR_LENGTH(evidence_store_ref_version) >= 1
    AND CHAR_LENGTH(evidence_write_ref_version) >= 1
    AND CHAR_LENGTH(evidence_read_ref_version) >= 1
    AND CHAR_LENGTH(evidence_delete_ref_version) >= 1
    AND CHAR_LENGTH(evidence_ca_ref_version) >= 1
    AND CHAR_LENGTH(evidence_kek_ref_version) >= 1
    AND CHAR_LENGTH(kek_ref_version) >= 1
    AND CHAR_LENGTH(capture_signing_ref_version) >= 1
    AND CHAR_LENGTH(acceptance_signing_ref_version) >= 1
    AND CHAR_LENGTH(catalog_signing_ref_version) >= 1
    AND CHAR_LENGTH(catalog_read_ref_version) >= 1
    AND CHAR_LENGTH(catalog_append_ref_version) >= 1
    AND CHAR_LENGTH(catalog_snapshot_ref_version) >= 1
    AND CHAR_LENGTH(nonce_hmac_ref_version) >= 1
    AND CHAR_LENGTH(status_relay_ref_version) >= 1
  ),
  CONSTRAINT chk_sb_config_reason CHECK (change_reason IS NULL OR OCTET_LENGTH(change_reason) BETWEEN 1 AND 512),
  CONSTRAINT chk_sb_config_created_by CHECK (OCTET_LENGTH(created_by) BETWEEN 1 AND 128)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_operations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-operation.v1',
  public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  operation_type ENUM('cancel', 'cleanup', 'ownership_resolution', 'provider_proof_register', 'finalization_resolution', 'manual_hold_update', 'config_update', 'promotion_create', 'promotion_revoke', 'catalog_scan', 'catalog_import', 'prune_execute', 'prune_retry', 'artifact_health_reconcile', 'orphan_gc', 'control_metadata_gc', 'evidence_gc') NOT NULL,
  target_type ENUM('backup', 'backup_staging', 'external_action', 'drill', 'restore_resource', 'preflight', 'artifact_verify', 'catalog_scan', 'catalog_import', 'prune_run', 'promotion', 'matrix', 'system') NOT NULL,
  target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retry_of_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  external_action_public_ids_canonical_json BLOB NOT NULL,
  external_action_public_ids_size_bytes INT UNSIGNED NOT NULL,
  external_action_public_ids_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status ENUM('pending', 'running', 'succeeded', 'failed') NOT NULL,
  result_resource_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  result_config_version BIGINT UNSIGNED NULL,
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  http_status SMALLINT UNSIGNED NULL,
  redacted_response_evidence_id BIGINT UNSIGNED NULL,
  redacted_response_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  claim_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  deadline_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_operation_public_id (public_id),
  UNIQUE KEY uk_sb_operation_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_operation_origin_type (origin_installation_id, public_id, operation_type),
  UNIQUE KEY uk_sb_operation_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_operation_retry (origin_installation_id, retry_of_operation_public_id),
  KEY idx_sb_operation_target (target_type, target_public_id, created_at, id),
  KEY idx_sb_operation_reconcile (status, next_reconcile_at, claim_expires_at),
  KEY idx_sb_operation_result_config (origin_installation_id, result_config_version),
  CONSTRAINT fk_sb_operation_retry FOREIGN KEY (origin_installation_id, retry_of_operation_public_id) REFERENCES system_backup_operations(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_operation_result_config FOREIGN KEY (origin_installation_id, result_config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_operation_response_evidence FOREIGN KEY (redacted_response_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_operation_schema CHECK (schema_version = 'system-backup-operation.v1'),
  CONSTRAINT chk_sb_operation_public_id CHECK (public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT chk_sb_operation_identity CHECK (
    origin_installation_id REGEXP '^installation_'
    AND ((actor_type = 'admin' AND actor_id REGEXP '^[0-9]+$') OR (actor_type = 'system' AND actor_id = 'system:controller'))
    AND endpoint REGEXP '^[A-Za-z][A-Za-z0-9_]{0,127}$'
    AND CHAR_LENGTH(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key REGEXP '^[A-Za-z0-9._:-]+$'
    AND (retry_of_operation_public_id IS NULL OR (
      retry_of_operation_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      AND retry_of_operation_public_id <> public_id
    ))
  ),
  CONSTRAINT chk_sb_operation_target_id CHECK (
    (target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'backup_staging' AND target_public_id REGEXP '^sbs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'external_action' AND target_public_id REGEXP '^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'drill' AND target_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'restore_resource' AND target_public_id REGEXP '^srr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'preflight' AND target_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'artifact_verify' AND target_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_scan' AND target_public_id REGEXP '^scs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_import' AND target_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'prune_run' AND target_public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'promotion' AND target_public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'matrix' AND target_public_id IN ('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node'))
    OR (target_type = 'system' AND target_public_id = origin_installation_id AND target_public_id REGEXP '^installation_')
  ),
  CONSTRAINT chk_sb_operation_request_hash CHECK (request_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_operation_external_actions CHECK (
    JSON_VALID(CONVERT(external_action_public_ids_canonical_json USING utf8mb4))
    AND JSON_TYPE(CONVERT(external_action_public_ids_canonical_json USING utf8mb4)) = 'ARRAY'
    AND JSON_LENGTH(CONVERT(external_action_public_ids_canonical_json USING utf8mb4)) <= 1000
    AND external_action_public_ids_size_bytes = OCTET_LENGTH(external_action_public_ids_canonical_json)
    AND external_action_public_ids_size_bytes BETWEEN 2 AND 65535
    AND external_action_public_ids_sha256 REGEXP '^[0-9a-f]{64}$'
    AND (operation_type NOT IN ('config_update', 'provider_proof_register', 'manual_hold_update', 'promotion_create', 'promotion_revoke')
      OR JSON_LENGTH(CONVERT(external_action_public_ids_canonical_json USING utf8mb4)) = 0)
  ),
  CONSTRAINT chk_sb_operation_failure CHECK (
    (status IN ('pending', 'running', 'succeeded') AND failure_category = 'none' AND failure_message IS NULL AND retryable = FALSE)
    OR (status = 'failed' AND failure_category <> 'none')
  ),
  CONSTRAINT chk_sb_operation_result CHECK (
    (status = 'succeeded' AND operation_type = 'config_update' AND result_config_version IS NOT NULL AND result_resource_public_id IS NULL)
    OR (status = 'succeeded' AND operation_type = 'provider_proof_register' AND result_config_version IS NULL AND result_resource_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (status = 'succeeded' AND operation_type = 'promotion_create' AND result_config_version IS NULL AND result_resource_public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (status = 'succeeded' AND operation_type = 'catalog_scan' AND result_config_version IS NULL AND result_resource_public_id REGEXP '^scs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (status = 'succeeded' AND operation_type = 'catalog_import' AND result_config_version IS NULL AND result_resource_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR ((status <> 'succeeded' OR operation_type NOT IN ('config_update', 'provider_proof_register', 'promotion_create', 'catalog_scan', 'catalog_import')) AND result_config_version IS NULL AND result_resource_public_id IS NULL)
  ),
  CONSTRAINT chk_sb_operation_sync_terminal CHECK (
    operation_type NOT IN ('config_update', 'provider_proof_register', 'manual_hold_update', 'promotion_create', 'promotion_revoke')
    OR status IN ('succeeded', 'failed')
  ),
  CONSTRAINT chk_sb_operation_response CHECK (
    (redacted_response_evidence_id IS NULL AND redacted_response_sha256 IS NULL)
    OR (status IN ('succeeded', 'failed') AND redacted_response_evidence_id IS NOT NULL AND redacted_response_sha256 REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_operation_claim CHECK (
    (claim_owner IS NULL AND claim_expires_at IS NULL)
    OR (status IN ('pending', 'running') AND claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_operation_reconcile CHECK (
    (status IN ('pending', 'running') AND next_reconcile_at IS NOT NULL)
    OR (status IN ('succeeded', 'failed') AND next_reconcile_at IS NULL)
  ),
  CONSTRAINT chk_sb_operation_timestamps CHECK (
    deadline_at > created_at
    AND ((status = 'pending' AND started_at IS NULL AND finished_at IS NULL)
      OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
      OR (status IN ('succeeded', 'failed') AND finished_at IS NOT NULL))
    AND (started_at IS NULL OR started_at >= created_at)
    AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))
  ),
  CONSTRAINT chk_sb_operation_http CHECK (http_status IS NULL OR (status IN ('succeeded', 'failed') AND http_status BETWEEN 100 AND 599)),
  CONSTRAINT chk_sb_operation_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @sb_installation_config_fk_exists = (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_backup_installation_state'
    AND CONSTRAINT_NAME = 'fk_sb_installation_active_config'
    AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sb_installation_config_fk_sql = IF(
  @sb_installation_config_fk_exists = 0,
  'ALTER TABLE system_backup_installation_state ADD CONSTRAINT fk_sb_installation_active_config FOREIGN KEY (origin_installation_id, active_config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT',
  'SELECT 1'
);
PREPARE sb_installation_config_fk_stmt FROM @sb_installation_config_fk_sql;
EXECUTE sb_installation_config_fk_stmt;
DEALLOCATE PREPARE sb_installation_config_fk_stmt;
