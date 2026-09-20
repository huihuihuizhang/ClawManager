CREATE TABLE IF NOT EXISTS system_backups (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-task.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('backup') NOT NULL DEFAULT 'backup',
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retry_of_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  status ENUM('pending', 'preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'validating', 'publishing', 'finalization_unknown', 'canceling', 'succeeded', 'failed', 'canceled') NOT NULL DEFAULT 'pending',
  pending_reason ENUM('none', 'global_capture_queue', 'kill_switch', 'dependency_backoff') NOT NULL DEFAULT 'none',
  attention_reason ENUM('none', 'external_result_unknown') NOT NULL DEFAULT 'none',
  can_cancel BOOLEAN NOT NULL DEFAULT TRUE,
  config_version BIGINT UNSIGNED NOT NULL,
  config_snapshot_json MEDIUMBLOB NOT NULL,
  config_snapshot_size_bytes INT UNSIGNED NOT NULL,
  config_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  heartbeat_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  deadline_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,

  source_orchestrator ENUM('kubernetes', 'k3s') NOT NULL,
  source_profile ENUM('cluster', 'single-node') NOT NULL,
  matrix_key ENUM('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node') NOT NULL,
  datasource_topology ENUM('in_cluster') NOT NULL DEFAULT 'in_cluster',
  runner ENUM('k8s', 'k3s') NOT NULL,
  task_purpose ENUM('acceptance', 'functional_test') NOT NULL DEFAULT 'acceptance',
  requested_parts SET('mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle') NOT NULL,

  artifact_uri VARBINARY(2048) NULL,
  artifact_immutable_version VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  manifest_uri VARBINARY(2048) NULL,
  manifest_immutable_version VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
  manifest_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  index_uri VARBINARY(2048) NULL,
  index_immutable_version VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
  index_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  marker_uri VARBINARY(2048) NULL,
  marker_immutable_version VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
  marker_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  acceptance_uri VARBINARY(2048) NULL,
  acceptance_immutable_version VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
  acceptance_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_committed_at DATETIME(6) NULL,
  artifact_read_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_read_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_ca_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_ca_ref_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_registration_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_registration_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_state ENUM('staging', 'committed', 'deleting', 'delete_failed', 'deleted', 'corrupt') NOT NULL DEFAULT 'staging',
  artifact_usable BOOLEAN NOT NULL DEFAULT FALSE,
  artifact_unusable_reason ENUM('none', 'not_committed', 'finalization_pending', 'deleting', 'delete_failed', 'deleted', 'corrupt', 'provider_unavailable', 'credential_unavailable', 'kek_unavailable', 'evidence_unavailable', 'verification_inconclusive') NOT NULL DEFAULT 'not_committed',
  artifact_last_health_at DATETIME(6) NULL,
  target_class ENUM('dr-ready-external', 'same-cluster-copy') NOT NULL,
  target_risks SET('source_overlap', 'same_failure_domain', 'artifact_credential_source_dependent', 'kek_source_dependent', 'signing_key_source_dependent', 'catalog_source_dependent', 'attestation_missing', 'attestation_expired', 'conditional_commit_unavailable', 'transport_unverified', 'broad_egress', 'provider_capability_degraded') NOT NULL,
  target_failure_domain_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  consistency ENUM('strong', 'bounded', 'weak') NULL,
  acceptance_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  eligibility_reason_codes SET('eligible', 'functional_test', 'task_not_succeeded', 'artifact_not_committed', 'required_part_failed', 'required_verifier_failed', 'staging_cleanup_failed', 'consistency_not_strong', 'disqualifying_warning', 'target_not_external', 'target_risk', 'attestation_invalid', 'kek_not_recoverable', 'catalog_unavailable', 'source_backup_not_eligible', 'source_artifact_unusable', 'manifest_drift', 'isolation_invalid', 'evidence_incomplete') NOT NULL DEFAULT 'task_not_succeeded',
  eligibility_decision_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  eligibility_decided_at DATETIME(6) NULL,
  manual_hold BOOLEAN NOT NULL DEFAULT FALSE,
  manual_hold_reason VARCHAR(512) NULL,
  manual_hold_actor VARCHAR(128) NULL,
  manual_hold_at DATETIME(6) NULL,
  promotion_hold BOOLEAN NOT NULL DEFAULT FALSE,
  artifact_bytes BIGINT UNSIGNED NULL,
  maintenance_lock_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  maintenance_fencing_token BIGINT UNSIGNED NULL,
  capture_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  capture_checkpoint_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  finalization_action_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  commit_started_at DATETIME(6) NULL,
  prune_guard_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_backup_public (public_id),
  UNIQUE KEY uk_sb_backup_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_backup_origin_matrix (origin_installation_id, public_id, matrix_key),
  UNIQUE KEY uk_sb_backup_origin_registration (origin_installation_id, public_id, artifact_registration_id, artifact_registration_hash),
  UNIQUE KEY uk_sb_backup_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_backup_status (origin_installation_id, status, next_reconcile_at, id),
  KEY idx_sb_backup_created (origin_installation_id, created_at, id),
  KEY idx_sb_backup_retry (retry_of_public_id),
  CONSTRAINT fk_sb_backup_config FOREIGN KEY (origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes) REFERENCES system_backup_configs(origin_installation_id, version, config_sha256, config_size_bytes) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_backup_retry FOREIGN KEY (retry_of_public_id) REFERENCES system_backups(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_backup_identity CHECK (
    schema_version = 'system-backup-task.v1' AND task_type = 'backup'
    AND public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND (retry_of_public_id IS NULL OR retry_of_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_backup_actor CHECK ((actor_type = 'admin' AND actor_id REGEXP '^[0-9]+$') OR (actor_type = 'system' AND actor_id = 'system:controller')),
  CONSTRAINT chk_sb_backup_request CHECK (
    CHAR_LENGTH(endpoint) BETWEEN 1 AND 128
    AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$'
    AND request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$'
    AND request_hash REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_backup_snapshot CHECK (
    config_snapshot_size_bytes BETWEEN 2 AND 262144
    AND OCTET_LENGTH(config_snapshot_json) = config_snapshot_size_bytes
    AND config_snapshot_sha256 REGEXP '^[0-9a-f]{64}$'
    AND JSON_VALID(CONVERT(config_snapshot_json USING utf8mb4))
  ),
  CONSTRAINT chk_sb_backup_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_backup_pending CHECK ((status = 'pending') OR pending_reason = 'none'),
  CONSTRAINT chk_sb_backup_attention CHECK ((status = 'finalization_unknown' AND attention_reason = 'external_result_unknown') OR (status <> 'finalization_unknown' AND attention_reason = 'none')),
  CONSTRAINT chk_sb_backup_cancel CHECK (can_cancel = (status IN ('pending', 'preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'validating', 'publishing') AND commit_started_at IS NULL)),
  CONSTRAINT chk_sb_backup_commit CHECK (
    (commit_started_at IS NULL AND finalization_action_public_id IS NULL)
    OR (commit_started_at IS NOT NULL AND commit_started_at >= COALESCE(started_at, created_at) AND status IN ('publishing', 'finalization_unknown', 'succeeded', 'failed'))
  ),
  CONSTRAINT chk_sb_backup_status CHECK (
    (status IN ('pending', 'preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'validating', 'publishing', 'canceling') AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE)
    OR (status = 'finalization_unknown' AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE AND commit_started_at IS NOT NULL)
    OR (status = 'succeeded' AND failure_category = 'none' AND finished_at IS NOT NULL AND retryable = FALSE)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
    OR (status = 'canceled' AND failure_category IN ('canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL AND retryable = FALSE)
  ),
  CONSTRAINT chk_sb_backup_retryable CHECK (retryable = FALSE OR (status = 'failed' AND failure_category IN ('not_ready', 'quiesce_timeout', 'deadline_exceeded', 'artifact_unavailable', 'encryption_key_unavailable', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'runner_failed', 'preflight_failed'))),
  CONSTRAINT chk_sb_backup_times CHECK (
    deadline_at >= created_at AND updated_at >= created_at
    AND ((status = 'pending' AND started_at IS NULL) OR (status <> 'pending' AND started_at IS NOT NULL))
    AND (started_at IS NULL OR started_at >= created_at)
    AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))
  ),
  CONSTRAINT chk_sb_backup_matrix CHECK ((source_orchestrator = 'kubernetes' AND runner = 'k8s' AND matrix_key IN ('k8s-cluster', 'k8s-single-node')) OR (source_orchestrator = 'k3s' AND runner = 'k3s' AND matrix_key IN ('k3s-cluster', 'k3s-single-node'))),
  CONSTRAINT chk_sb_backup_profile CHECK ((source_profile = 'cluster' AND matrix_key IN ('k8s-cluster', 'k3s-cluster')) OR (source_profile = 'single-node' AND matrix_key IN ('k8s-single-node', 'k3s-single-node'))),
  CONSTRAINT chk_sb_backup_parts CHECK (requested_parts <> ''),
  CONSTRAINT chk_sb_backup_hashes CHECK (
    artifact_read_identity_hash REGEXP '^[0-9a-f]{64}$' AND artifact_ca_identity_hash REGEXP '^[0-9a-f]{64}$'
    AND (artifact_checksum IS NULL OR artifact_checksum REGEXP '^[0-9a-f]{64}$')
    AND (manifest_checksum IS NULL OR manifest_checksum REGEXP '^[0-9a-f]{64}$')
    AND (index_checksum IS NULL OR index_checksum REGEXP '^[0-9a-f]{64}$')
    AND (marker_checksum IS NULL OR marker_checksum REGEXP '^[0-9a-f]{64}$')
    AND (acceptance_checksum IS NULL OR acceptance_checksum REGEXP '^[0-9a-f]{64}$')
    AND (artifact_registration_hash IS NULL OR artifact_registration_hash REGEXP '^[0-9a-f]{64}$')
    AND (eligibility_decision_hash IS NULL OR eligibility_decision_hash REGEXP '^[0-9a-f]{64}$')
    AND (capture_certificate_sha256 IS NULL OR capture_certificate_sha256 REGEXP '^[0-9a-f]{64}$')
    AND (capture_checkpoint_sha256 IS NULL OR capture_checkpoint_sha256 REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_backup_locators CHECK (
    ((artifact_uri IS NULL AND artifact_immutable_version IS NULL AND artifact_checksum IS NULL) OR (artifact_uri IS NOT NULL AND artifact_immutable_version IS NOT NULL AND artifact_checksum IS NOT NULL))
    AND ((manifest_uri IS NULL AND manifest_immutable_version IS NULL AND manifest_checksum IS NULL) OR (manifest_uri IS NOT NULL AND manifest_immutable_version IS NOT NULL AND manifest_checksum IS NOT NULL))
    AND ((index_uri IS NULL AND index_immutable_version IS NULL AND index_checksum IS NULL) OR (index_uri IS NOT NULL AND index_immutable_version IS NOT NULL AND index_checksum IS NOT NULL))
    AND ((marker_uri IS NULL AND marker_immutable_version IS NULL AND marker_checksum IS NULL) OR (marker_uri IS NOT NULL AND marker_immutable_version IS NOT NULL AND marker_checksum IS NOT NULL))
    AND ((acceptance_uri IS NULL AND acceptance_immutable_version IS NULL AND acceptance_checksum IS NULL) OR (acceptance_uri IS NOT NULL AND acceptance_immutable_version IS NOT NULL AND acceptance_checksum IS NOT NULL))
  ),
  CONSTRAINT chk_sb_backup_artifact CHECK (
    (artifact_state = 'staging' AND artifact_committed_at IS NULL AND artifact_usable = FALSE AND artifact_unusable_reason = 'not_committed')
    OR (artifact_state = 'committed' AND artifact_uri IS NOT NULL AND artifact_immutable_version IS NOT NULL AND artifact_checksum IS NOT NULL AND manifest_uri IS NOT NULL AND manifest_immutable_version IS NOT NULL AND manifest_checksum IS NOT NULL AND index_uri IS NOT NULL AND index_immutable_version IS NOT NULL AND index_checksum IS NOT NULL AND marker_uri IS NOT NULL AND marker_immutable_version IS NOT NULL AND marker_checksum IS NOT NULL AND artifact_committed_at IS NOT NULL AND ((artifact_usable = TRUE AND artifact_unusable_reason = 'none') OR (artifact_usable = FALSE AND artifact_unusable_reason NOT IN ('none', 'not_committed', 'deleting', 'delete_failed', 'deleted', 'corrupt'))))
    OR (artifact_state = 'deleting' AND artifact_usable = FALSE AND artifact_unusable_reason = 'deleting')
    OR (artifact_state = 'delete_failed' AND artifact_usable = FALSE AND artifact_unusable_reason = 'delete_failed')
    OR (artifact_state = 'deleted' AND artifact_usable = FALSE AND artifact_unusable_reason = 'deleted')
    OR (artifact_state = 'corrupt' AND artifact_usable = FALSE AND artifact_unusable_reason = 'corrupt')
  ),
  CONSTRAINT chk_sb_backup_registration CHECK ((artifact_registration_id IS NULL AND artifact_registration_hash IS NULL) OR (artifact_registration_id IS NOT NULL AND artifact_registration_hash IS NOT NULL)),
  CONSTRAINT chk_sb_backup_eligibility CHECK (
    (acceptance_eligible = TRUE AND status = 'succeeded' AND eligibility_reason_codes = 'eligible' AND eligibility_decision_hash IS NOT NULL AND eligibility_decided_at IS NOT NULL AND artifact_registration_id IS NOT NULL AND artifact_registration_hash IS NOT NULL)
    OR (acceptance_eligible = FALSE AND eligibility_reason_codes <> '' AND NOT FIND_IN_SET('eligible', eligibility_reason_codes) AND ((eligibility_decision_hash IS NULL AND eligibility_decided_at IS NULL) OR (eligibility_decision_hash IS NOT NULL AND eligibility_decided_at IS NOT NULL)))
  ),
  CONSTRAINT chk_sb_backup_hold CHECK ((manual_hold = FALSE AND manual_hold_reason IS NULL AND manual_hold_actor IS NULL AND manual_hold_at IS NULL) OR (manual_hold = TRUE AND manual_hold_reason IS NOT NULL AND manual_hold_actor IS NOT NULL AND manual_hold_at IS NOT NULL)),
  CONSTRAINT chk_sb_backup_lock CHECK ((maintenance_lock_owner IS NULL AND maintenance_fencing_token IS NULL) OR (maintenance_lock_owner IS NOT NULL AND maintenance_fencing_token IS NOT NULL)),
  CONSTRAINT chk_sb_backup_action CHECK (finalization_action_public_id IS NULL OR finalization_action_public_id REGEXP '^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT chk_sb_backup_versions CHECK (row_version >= 1 AND prune_guard_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_restore_drills (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-task.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('drill') NOT NULL DEFAULT 'drill',
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retry_of_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  status ENUM('pending', 'preflighting', 'provisioning', 'restoring', 'normalizing', 'verifying', 'canceling', 'succeeded', 'failed', 'canceled') NOT NULL DEFAULT 'pending',
  pending_reason ENUM('none', 'global_capture_queue', 'kill_switch', 'dependency_backoff') NOT NULL DEFAULT 'none',
  attention_reason ENUM('none', 'external_result_unknown') NOT NULL DEFAULT 'none',
  can_cancel BOOLEAN NOT NULL DEFAULT TRUE,
  config_version BIGINT UNSIGNED NOT NULL,
  config_snapshot_json MEDIUMBLOB NOT NULL,
  config_snapshot_size_bytes INT UNSIGNED NOT NULL,
  config_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  heartbeat_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  deadline_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,

  source_artifact_type ENUM('backup', 'catalog_import') NOT NULL,
  source_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  local_source_backup_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN source_artifact_type = 'backup' THEN source_public_id ELSE NULL END) STORED,
  source_manifest_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  source_acceptance_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  source_catalog_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  task_purpose ENUM('acceptance', 'functional_test') NOT NULL DEFAULT 'acceptance',
  target_profile ENUM('cluster', 'single-node') NOT NULL,
  restore_target_config_ref VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  restore_target_config_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  cleanup_policy ENUM('delete-on-success', 'retain-always') NOT NULL,
  cleanup_status ENUM('not_started', 'pending', 'running', 'succeeded', 'failed', 'partial_failed', 'retained') NOT NULL DEFAULT 'not_started',
  cleanup_failure_code ENUM('none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch', 'checksum_mismatch', 'ownership_unknown', 'residual_data', 'internal') NOT NULL DEFAULT 'none',
  preflight_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  preflight_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  diff_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  diff_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  verifier_aggregate_status ENUM('passed', 'warning', 'failed', 'skipped') NOT NULL DEFAULT 'skipped',
  verifier_passed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_warning INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_failed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_skipped INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_report_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  verifier_report_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  consistency ENUM('strong', 'bounded', 'weak') NULL,
  acceptance_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  eligibility_reason_codes SET('eligible', 'functional_test', 'task_not_succeeded', 'artifact_not_committed', 'required_part_failed', 'required_verifier_failed', 'staging_cleanup_failed', 'consistency_not_strong', 'disqualifying_warning', 'target_not_external', 'target_risk', 'attestation_invalid', 'kek_not_recoverable', 'catalog_unavailable', 'source_backup_not_eligible', 'source_artifact_unusable', 'manifest_drift', 'isolation_invalid', 'evidence_incomplete') NOT NULL DEFAULT 'task_not_succeeded',
  eligibility_decision_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  eligibility_decided_at DATETIME(6) NULL,
  maintenance_lock_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  maintenance_fencing_token BIGINT UNSIGNED NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_drill_public (public_id),
  UNIQUE KEY uk_sb_drill_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_drill_local_source (origin_installation_id, public_id, local_source_backup_public_id),
  UNIQUE KEY uk_sb_drill_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_drill_status (origin_installation_id, status, next_reconcile_at, id),
  KEY idx_sb_drill_created (origin_installation_id, created_at, id),
  KEY idx_sb_drill_source (source_artifact_type, source_public_id),
  CONSTRAINT fk_sb_drill_config FOREIGN KEY (origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes) REFERENCES system_backup_configs(origin_installation_id, version, config_sha256, config_size_bytes) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_drill_retry FOREIGN KEY (retry_of_public_id) REFERENCES system_restore_drills(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_drill_identity CHECK (
    schema_version = 'system-backup-task.v1' AND task_type = 'drill'
    AND public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND (retry_of_public_id IS NULL OR retry_of_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_drill_actor CHECK ((actor_type = 'admin' AND actor_id REGEXP '^[0-9]+$') OR (actor_type = 'system' AND actor_id = 'system:controller')),
  CONSTRAINT chk_sb_drill_request CHECK (CHAR_LENGTH(endpoint) BETWEEN 1 AND 128 AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$' AND request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$' AND request_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_drill_snapshot CHECK (config_snapshot_size_bytes BETWEEN 2 AND 262144 AND OCTET_LENGTH(config_snapshot_json) = config_snapshot_size_bytes AND config_snapshot_sha256 REGEXP '^[0-9a-f]{64}$' AND JSON_VALID(CONVERT(config_snapshot_json USING utf8mb4))),
  CONSTRAINT chk_sb_drill_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_drill_reasons CHECK (((status = 'pending') OR pending_reason = 'none') AND attention_reason = 'none'),
  CONSTRAINT chk_sb_drill_cancel CHECK (can_cancel = (status IN ('pending', 'preflighting', 'provisioning', 'restoring', 'normalizing', 'verifying'))),
  CONSTRAINT chk_sb_drill_status CHECK (
    (status IN ('pending', 'preflighting', 'provisioning', 'restoring', 'normalizing', 'verifying', 'canceling') AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE)
    OR (status = 'succeeded' AND failure_category = 'none' AND finished_at IS NOT NULL AND retryable = FALSE)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
    OR (status = 'canceled' AND failure_category IN ('canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL AND retryable = FALSE)
  ),
  CONSTRAINT chk_sb_drill_retryable CHECK (retryable = FALSE OR (status = 'failed' AND failure_category IN ('not_ready', 'quiesce_timeout', 'deadline_exceeded', 'artifact_unavailable', 'encryption_key_unavailable', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'runner_failed', 'preflight_failed'))),
  CONSTRAINT chk_sb_drill_times CHECK (deadline_at >= created_at AND updated_at >= created_at AND ((status = 'pending' AND started_at IS NULL) OR (status <> 'pending' AND started_at IS NOT NULL)) AND (started_at IS NULL OR started_at >= created_at) AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))),
  CONSTRAINT chk_sb_drill_source CHECK ((source_artifact_type = 'backup' AND source_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') OR (source_artifact_type = 'catalog_import' AND source_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
  CONSTRAINT chk_sb_drill_hashes CHECK (
    restore_target_config_hash REGEXP '^[0-9a-f]{64}$'
    AND (source_manifest_checksum IS NULL OR source_manifest_checksum REGEXP '^[0-9a-f]{64}$')
    AND (source_acceptance_checksum IS NULL OR source_acceptance_checksum REGEXP '^[0-9a-f]{64}$')
    AND (source_catalog_checksum IS NULL OR source_catalog_checksum REGEXP '^[0-9a-f]{64}$')
    AND (eligibility_decision_hash IS NULL OR eligibility_decision_hash REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_drill_cleanup CHECK (((cleanup_status IN ('failed', 'partial_failed')) AND cleanup_failure_code <> 'none') OR (cleanup_status NOT IN ('failed', 'partial_failed') AND cleanup_failure_code = 'none')),
  CONSTRAINT chk_sb_drill_evidence CHECK (
    ((preflight_evidence_public_id IS NULL AND preflight_evidence_sha256 IS NULL) OR (preflight_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND preflight_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
    AND ((diff_evidence_public_id IS NULL AND diff_evidence_sha256 IS NULL) OR (diff_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND diff_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
    AND ((verifier_report_evidence_public_id IS NULL AND verifier_report_evidence_sha256 IS NULL) OR (verifier_report_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND verifier_report_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
  ),
  CONSTRAINT chk_sb_drill_eligibility CHECK (
    (acceptance_eligible = TRUE AND status = 'succeeded' AND task_purpose = 'acceptance' AND cleanup_policy = 'delete-on-success' AND cleanup_status = 'succeeded' AND eligibility_reason_codes = 'eligible' AND eligibility_decision_hash IS NOT NULL AND eligibility_decided_at IS NOT NULL)
    OR (acceptance_eligible = FALSE AND eligibility_reason_codes <> '' AND NOT FIND_IN_SET('eligible', eligibility_reason_codes) AND ((eligibility_decision_hash IS NULL AND eligibility_decided_at IS NULL) OR (eligibility_decision_hash IS NOT NULL AND eligibility_decided_at IS NOT NULL)))
  ),
  CONSTRAINT chk_sb_drill_lock CHECK ((maintenance_lock_owner IS NULL AND maintenance_fencing_token IS NULL) OR (maintenance_lock_owner IS NOT NULL AND maintenance_fencing_token IS NOT NULL)),
  CONSTRAINT chk_sb_drill_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_preflights (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-task.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('preflight') NOT NULL DEFAULT 'preflight',
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retry_of_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  status ENUM('pending', 'running', 'canceling', 'succeeded', 'failed', 'canceled') NOT NULL DEFAULT 'pending',
  pending_reason ENUM('none', 'global_capture_queue', 'kill_switch', 'dependency_backoff') NOT NULL DEFAULT 'none',
  attention_reason ENUM('none', 'external_result_unknown') NOT NULL DEFAULT 'none',
  can_cancel BOOLEAN NOT NULL DEFAULT TRUE,
  config_version BIGINT UNSIGNED NOT NULL,
  config_snapshot_json MEDIUMBLOB NOT NULL,
  config_snapshot_size_bytes INT UNSIGNED NOT NULL,
  config_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  heartbeat_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  deadline_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,

  source_artifact_type ENUM('backup', 'catalog_import') NOT NULL,
  source_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_manifest_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  source_acceptance_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  source_catalog_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  preflight_mode ENUM('production_readonly', 'functional_test') NOT NULL DEFAULT 'production_readonly',
  target_profile ENUM('cluster', 'single-node') NOT NULL,
  restore_target_config_ref VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  restore_target_config_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_compatibility ENUM('supported', 'compatible_with_warnings', 'unsupported') NOT NULL,
  report_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  report_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  diff_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  diff_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  report_validity_reason ENUM('pending', 'valid', 'functional_test_only', 'source_changed', 'dependency_unhealthy', 'report_expired', 'evidence_unavailable', 'incomplete') NOT NULL DEFAULT 'pending',
  verifier_aggregate_status ENUM('passed', 'warning', 'failed', 'skipped') NOT NULL DEFAULT 'skipped',
  verifier_passed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_warning INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_failed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_skipped INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_report_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  verifier_report_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_preflight_public (public_id),
  UNIQUE KEY uk_sb_preflight_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_preflight_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_preflight_status (origin_installation_id, status, next_reconcile_at, id),
  KEY idx_sb_preflight_source (source_artifact_type, source_public_id),
  CONSTRAINT fk_sb_preflight_config FOREIGN KEY (origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes) REFERENCES system_backup_configs(origin_installation_id, version, config_sha256, config_size_bytes) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_preflight_retry FOREIGN KEY (retry_of_public_id) REFERENCES system_backup_preflights(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_preflight_identity CHECK (schema_version = 'system-backup-task.v1' AND task_type = 'preflight' AND public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$' AND (retry_of_public_id IS NULL OR retry_of_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
  CONSTRAINT chk_sb_preflight_actor CHECK ((actor_type = 'admin' AND actor_id REGEXP '^[0-9]+$') OR (actor_type = 'system' AND actor_id = 'system:controller')),
  CONSTRAINT chk_sb_preflight_request CHECK (CHAR_LENGTH(endpoint) BETWEEN 1 AND 128 AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$' AND request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$' AND request_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_preflight_snapshot CHECK (config_snapshot_size_bytes BETWEEN 2 AND 262144 AND OCTET_LENGTH(config_snapshot_json) = config_snapshot_size_bytes AND config_snapshot_sha256 REGEXP '^[0-9a-f]{64}$' AND JSON_VALID(CONVERT(config_snapshot_json USING utf8mb4))),
  CONSTRAINT chk_sb_preflight_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_preflight_reasons CHECK (((status = 'pending') OR pending_reason = 'none') AND attention_reason = 'none'),
  CONSTRAINT chk_sb_preflight_cancel CHECK (can_cancel = (status IN ('pending', 'running'))),
  CONSTRAINT chk_sb_preflight_status CHECK (
    (status IN ('pending', 'running', 'canceling') AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE)
    OR (status = 'succeeded' AND failure_category = 'none' AND finished_at IS NOT NULL AND retryable = FALSE)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
    OR (status = 'canceled' AND failure_category IN ('canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL AND retryable = FALSE)
  ),
  CONSTRAINT chk_sb_preflight_retryable CHECK (retryable = FALSE OR (status = 'failed' AND failure_category IN ('not_ready', 'quiesce_timeout', 'deadline_exceeded', 'artifact_unavailable', 'encryption_key_unavailable', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'runner_failed', 'preflight_failed'))),
  CONSTRAINT chk_sb_preflight_times CHECK (deadline_at >= created_at AND updated_at >= created_at AND ((status = 'pending' AND started_at IS NULL) OR (status <> 'pending' AND started_at IS NOT NULL)) AND (started_at IS NULL OR started_at >= created_at) AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))),
  CONSTRAINT chk_sb_preflight_source CHECK ((source_artifact_type = 'backup' AND source_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') OR (source_artifact_type = 'catalog_import' AND source_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
  CONSTRAINT chk_sb_preflight_hashes CHECK (restore_target_config_hash REGEXP '^[0-9a-f]{64}$' AND (source_manifest_checksum IS NULL OR source_manifest_checksum REGEXP '^[0-9a-f]{64}$') AND (source_acceptance_checksum IS NULL OR source_acceptance_checksum REGEXP '^[0-9a-f]{64}$') AND (source_catalog_checksum IS NULL OR source_catalog_checksum REGEXP '^[0-9a-f]{64}$')),
  CONSTRAINT chk_sb_preflight_evidence CHECK (
    ((report_evidence_public_id IS NULL AND report_evidence_sha256 IS NULL) OR (report_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND report_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
    AND ((diff_evidence_public_id IS NULL AND diff_evidence_sha256 IS NULL) OR (diff_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND diff_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
    AND ((verifier_report_evidence_public_id IS NULL AND verifier_report_evidence_sha256 IS NULL) OR (verifier_report_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND verifier_report_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
  ),
  CONSTRAINT chk_sb_preflight_mode CHECK ((preflight_mode = 'functional_test' AND report_validity_reason <> 'valid') OR preflight_mode = 'production_readonly'),
  CONSTRAINT chk_sb_preflight_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_artifact_verifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-task.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_type ENUM('artifact_verify') NOT NULL DEFAULT 'artifact_verify',
  actor_type ENUM('admin', 'system') NOT NULL,
  actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retry_of_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  status ENUM('pending', 'running', 'canceling', 'succeeded', 'failed', 'canceled') NOT NULL DEFAULT 'pending',
  pending_reason ENUM('none', 'global_capture_queue', 'kill_switch', 'dependency_backoff') NOT NULL DEFAULT 'none',
  attention_reason ENUM('none', 'external_result_unknown') NOT NULL DEFAULT 'none',
  can_cancel BOOLEAN NOT NULL DEFAULT TRUE,
  config_version BIGINT UNSIGNED NOT NULL,
  config_snapshot_json MEDIUMBLOB NOT NULL,
  config_snapshot_size_bytes INT UNSIGNED NOT NULL,
  config_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  heartbeat_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  deadline_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,

  verification_scope ENUM('health', 'full') NOT NULL,
  source_artifact_type ENUM('backup', 'catalog_import') NOT NULL,
  source_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observed_manifest_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_index_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_marker_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_acceptance_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  observed_catalog_checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  health_report_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  health_report_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_state_before ENUM('staging', 'committed', 'deleting', 'delete_failed', 'deleted', 'corrupt') NULL,
  artifact_state_after ENUM('staging', 'committed', 'deleting', 'delete_failed', 'deleted', 'corrupt') NULL,
  usable_before BOOLEAN NOT NULL DEFAULT FALSE,
  usable_after BOOLEAN NOT NULL DEFAULT FALSE,
  unusable_reason_before ENUM('none', 'not_committed', 'finalization_pending', 'deleting', 'delete_failed', 'deleted', 'corrupt', 'verification_pending', 'catalog_tombstoned', 'acceptance_invalid', 'provider_unavailable', 'credential_unavailable', 'kek_unavailable', 'signing_key_unavailable', 'catalog_unavailable', 'evidence_unavailable', 'verification_inconclusive') NOT NULL,
  unusable_reason_after ENUM('none', 'not_committed', 'finalization_pending', 'deleting', 'delete_failed', 'deleted', 'corrupt', 'verification_pending', 'catalog_tombstoned', 'acceptance_invalid', 'provider_unavailable', 'credential_unavailable', 'kek_unavailable', 'signing_key_unavailable', 'catalog_unavailable', 'evidence_unavailable', 'verification_inconclusive') NOT NULL,
  decision_reason ENUM('pending', 'unchanged', 'restored_usable', 'marked_unusable', 'marked_corrupt', 'catalog_tombstoned', 'verification_inconclusive') NOT NULL DEFAULT 'pending',
  verifier_aggregate_status ENUM('passed', 'warning', 'failed', 'skipped') NOT NULL DEFAULT 'skipped',
  verifier_passed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_warning INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_failed INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_skipped INT UNSIGNED NOT NULL DEFAULT 0,
  verifier_report_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  verifier_report_evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_verify_public (public_id),
  UNIQUE KEY uk_sb_verify_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_verify_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key),
  KEY idx_sb_verify_status (origin_installation_id, status, next_reconcile_at, id),
  KEY idx_sb_verify_source (source_artifact_type, source_public_id),
  CONSTRAINT fk_sb_verify_config FOREIGN KEY (origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes) REFERENCES system_backup_configs(origin_installation_id, version, config_sha256, config_size_bytes) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_verify_retry FOREIGN KEY (retry_of_public_id) REFERENCES system_backup_artifact_verifications(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_verify_identity CHECK (schema_version = 'system-backup-task.v1' AND task_type = 'artifact_verify' AND public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$' AND (retry_of_public_id IS NULL OR retry_of_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
  CONSTRAINT chk_sb_verify_actor CHECK ((actor_type = 'admin' AND actor_id REGEXP '^[0-9]+$') OR (actor_type = 'system' AND actor_id = 'system:controller')),
  CONSTRAINT chk_sb_verify_request CHECK (CHAR_LENGTH(endpoint) BETWEEN 1 AND 128 AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$' AND request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$' AND request_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT chk_sb_verify_snapshot CHECK (config_snapshot_size_bytes BETWEEN 2 AND 262144 AND OCTET_LENGTH(config_snapshot_json) = config_snapshot_size_bytes AND config_snapshot_sha256 REGEXP '^[0-9a-f]{64}$' AND JSON_VALID(CONVERT(config_snapshot_json USING utf8mb4))),
  CONSTRAINT chk_sb_verify_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_verify_reasons CHECK (((status = 'pending') OR pending_reason = 'none') AND attention_reason = 'none'),
  CONSTRAINT chk_sb_verify_cancel CHECK (can_cancel = (status IN ('pending', 'running'))),
  CONSTRAINT chk_sb_verify_status CHECK (
    (status IN ('pending', 'running', 'canceling') AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE)
    OR (status = 'succeeded' AND failure_category = 'none' AND finished_at IS NOT NULL AND retryable = FALSE)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
    OR (status = 'canceled' AND failure_category IN ('canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL AND retryable = FALSE)
  ),
  CONSTRAINT chk_sb_verify_retryable CHECK (retryable = FALSE OR (status = 'failed' AND failure_category IN ('not_ready', 'quiesce_timeout', 'deadline_exceeded', 'artifact_unavailable', 'encryption_key_unavailable', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'runner_failed', 'preflight_failed'))),
  CONSTRAINT chk_sb_verify_times CHECK (deadline_at >= created_at AND updated_at >= created_at AND ((status = 'pending' AND started_at IS NULL) OR (status <> 'pending' AND started_at IS NOT NULL)) AND (started_at IS NULL OR started_at >= created_at) AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))),
  CONSTRAINT chk_sb_verify_source CHECK ((source_artifact_type = 'backup' AND source_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND artifact_state_before IS NOT NULL AND artifact_state_after IS NOT NULL) OR (source_artifact_type = 'catalog_import' AND source_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND artifact_state_before IS NULL AND artifact_state_after IS NULL)),
  CONSTRAINT chk_sb_verify_hashes CHECK (
    (observed_manifest_checksum IS NULL OR observed_manifest_checksum REGEXP '^[0-9a-f]{64}$')
    AND (observed_index_checksum IS NULL OR observed_index_checksum REGEXP '^[0-9a-f]{64}$')
    AND (observed_marker_checksum IS NULL OR observed_marker_checksum REGEXP '^[0-9a-f]{64}$')
    AND (observed_acceptance_checksum IS NULL OR observed_acceptance_checksum REGEXP '^[0-9a-f]{64}$')
    AND (observed_catalog_checksum IS NULL OR observed_catalog_checksum REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_verify_evidence CHECK (
    ((health_report_evidence_public_id IS NULL AND health_report_evidence_sha256 IS NULL) OR (health_report_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND health_report_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
    AND ((verifier_report_evidence_public_id IS NULL AND verifier_report_evidence_sha256 IS NULL) OR (verifier_report_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND verifier_report_evidence_sha256 REGEXP '^[0-9a-f]{64}$'))
  ),
  CONSTRAINT chk_sb_verify_usable CHECK ((usable_before = TRUE AND unusable_reason_before = 'none') OR (usable_before = FALSE AND unusable_reason_before <> 'none')),
  CONSTRAINT chk_sb_verify_result CHECK ((usable_after = TRUE AND unusable_reason_after = 'none') OR (usable_after = FALSE AND unusable_reason_after <> 'none')),
  CONSTRAINT chk_sb_verify_row_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_attempts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('backup', 'drill', 'preflight', 'artifact_verify') NOT NULL,
  target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_no INT UNSIGNED NOT NULL,
  phase ENUM('capture', 'secret_capture', 'publish', 'restore', 'normalize', 'verify', 'preflight') NOT NULL,
  status ENUM('preparing', 'running', 'sealed', 'succeeded', 'failed', 'canceled') NOT NULL DEFAULT 'preparing',
  checkpoint_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  failure_message VARCHAR(2048) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_attempt_unit (target_type, target_public_id, attempt_no, phase),
  KEY idx_sb_attempt_target (target_type, target_public_id, created_at, id),
  CONSTRAINT chk_sb_attempt_target CHECK (
    (target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'drill' AND target_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'preflight' AND target_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'artifact_verify' AND target_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_attempt_phase CHECK (
    (target_type = 'backup' AND phase IN ('capture', 'secret_capture', 'publish'))
    OR (target_type = 'drill' AND phase IN ('restore', 'normalize', 'verify'))
    OR (target_type = 'preflight' AND phase = 'preflight')
    OR (target_type = 'artifact_verify' AND phase = 'verify')
  ),
  CONSTRAINT chk_sb_attempt_sealed CHECK (
    (status = 'sealed' AND target_type = 'backup' AND phase IN ('capture', 'secret_capture'))
    OR (status <> 'sealed' AND NOT (status = 'succeeded' AND target_type = 'backup' AND phase IN ('capture', 'secret_capture')))
  ),
  CONSTRAINT chk_sb_attempt_status CHECK (
    (status IN ('preparing', 'running') AND failure_category = 'none' AND finished_at IS NULL)
    OR (status IN ('sealed', 'succeeded') AND failure_category = 'none' AND finished_at IS NOT NULL)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
    OR (status = 'canceled' AND failure_category IN ('canceled_by_actor', 'canceled_by_shutdown') AND finished_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_attempt_times CHECK (
    attempt_no >= 1 AND row_version >= 1 AND updated_at >= created_at
    AND ((status = 'preparing' AND started_at IS NULL) OR (status <> 'preparing' AND started_at IS NOT NULL))
    AND (started_at IS NULL OR started_at >= created_at)
    AND (finished_at IS NULL OR finished_at >= COALESCE(started_at, created_at))
  ),
  CONSTRAINT chk_sb_attempt_hashes CHECK (
    (checkpoint_sha256 IS NULL OR checkpoint_sha256 REGEXP '^[0-9a-f]{64}$')
    AND (certificate_sha256 IS NULL OR (certificate_sha256 REGEXP '^[0-9a-f]{64}$' AND target_type = 'backup' AND phase IN ('capture', 'secret_capture') AND status = 'sealed'))
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
