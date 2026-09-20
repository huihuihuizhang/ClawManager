CREATE TABLE IF NOT EXISTS system_backup_prune_runs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-prune-run.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  create_actor_type ENUM('admin', 'system') NOT NULL,
  create_actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  create_endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  create_idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  create_request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  older_than DATETIME(6) NOT NULL,
  status ENUM('planning', 'dry_run_created', 'executing', 'partial_failed', 'succeeded', 'failed', 'expired') NOT NULL DEFAULT 'planning',
  retryable BOOLEAN NOT NULL DEFAULT FALSE,
  candidate_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  candidate_plan_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  candidate_count INT UNSIGNED NULL,
  candidate_item_count INT UNSIGNED NULL,
  candidate_bytes BIGINT UNSIGNED NULL,
  candidate_expires_at DATETIME(6) NULL,
  confirmation_status ENUM('none', 'issued', 'consumed', 'expired') NOT NULL DEFAULT 'none',
  confirmation_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_actor_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_candidate_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  confirmation_cutoff_at DATETIME(6) NULL,
  confirmation_config_version BIGINT UNSIGNED NULL,
  confirmation_prune_run_row_version BIGINT UNSIGNED NULL,
  confirmation_issued_at DATETIME(6) NULL,
  confirmation_expires_at DATETIME(6) NULL,
  confirmation_consumed_at DATETIME(6) NULL,
  execution_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  failure_category ENUM('none', 'canceled_by_actor', 'canceled_by_shutdown', 'validation_failed', 'permission_denied', 'not_found', 'not_ready', 'conflict_active_job', 'unsupported_runner_p1', 'unsupported_profile_p1', 'unsupported_datasource_p1', 'unsupported_schema', 'backup_target_risk_rejected', 'isolation_invalid', 'writer_registry_drift', 'quiesce_timeout', 'quiesce_resume_failed', 'capacity_exceeded', 'deadline_exceeded', 'preflight_failed', 'normalization_failed', 'control_evidence_invalid', 'artifact_unavailable', 'artifact_conflict', 'checksum_mismatch', 'signature_invalid', 'encryption_key_unavailable', 'kek_permission_denied', 'signing_key_unavailable', 'finalizer_request_unavailable', 'catalog_unavailable', 'catalog_conflict', 'catalog_tombstone_failed', 'secret_bundle_failed', 'redaction_failed', 'audit_failed', 'evidence_incomplete', 'staging_cleanup_failed', 'cleanup_unsafe_target', 'confirmation_invalid', 'fencing_token_lost', 'coordination_invalid', 'artifact_delete_failed', 'runner_failed', 'internal_error') NOT NULL DEFAULT 'none',
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  started_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  execution_started_at DATETIME(6) NULL,
  execution_finished_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_prune_run_public (public_id),
  UNIQUE KEY uk_sb_prune_run_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_prune_run_origin_id (origin_installation_id, id),
  UNIQUE KEY uk_sb_prune_run_create (origin_installation_id, create_actor_type, create_actor_id, create_endpoint, create_idempotency_key),
  UNIQUE KEY uk_sb_prune_run_confirmation_id (origin_installation_id, confirmation_id),
  UNIQUE KEY uk_sb_prune_run_confirmation (origin_installation_id, confirmation_actor_id, confirmation_endpoint, confirmation_idempotency_key),
  KEY idx_sb_prune_run_status (origin_installation_id, status, next_reconcile_at, id),
  KEY idx_sb_prune_run_history (origin_installation_id, created_at, id),
  KEY idx_sb_prune_run_operation (last_operation_public_id),
  CONSTRAINT fk_sb_prune_run_config FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_prune_run_confirmation_config FOREIGN KEY (origin_installation_id, confirmation_config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_prune_run_operation FOREIGN KEY (last_operation_public_id) REFERENCES system_backup_operations(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_prune_run_identity CHECK (
    schema_version = 'system-backup-prune-run.v1'
    AND public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
  ),
  CONSTRAINT chk_sb_prune_run_create CHECK (
    ((create_actor_type = 'admin' AND create_actor_id REGEXP '^[0-9]+$') OR (create_actor_type = 'system' AND create_actor_id = 'system:controller'))
    AND create_endpoint = 'createSystemBackupPruneDryRun'
    AND create_idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$'
    AND create_request_hash REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT chk_sb_prune_run_candidate CHECK (
    (status = 'planning' AND candidate_hash IS NULL AND candidate_plan_hash IS NULL AND candidate_count IS NULL AND candidate_item_count IS NULL AND candidate_bytes IS NULL AND candidate_expires_at IS NULL)
    OR (status <> 'planning' AND candidate_hash IS NOT NULL AND candidate_hash REGEXP '^[0-9a-f]{64}$' AND candidate_plan_hash IS NOT NULL AND candidate_plan_hash REGEXP '^[0-9a-f]{64}$' AND candidate_count IS NOT NULL AND candidate_count BETWEEN 0 AND 1000000 AND candidate_item_count IS NOT NULL AND candidate_item_count BETWEEN 0 AND 1000000 AND candidate_bytes IS NOT NULL AND candidate_expires_at IS NOT NULL AND candidate_expires_at > started_at)
  ),
  CONSTRAINT chk_sb_prune_run_confirmation CHECK (
    (confirmation_status = 'none' AND confirmation_id IS NULL AND confirmation_actor_id IS NULL AND confirmation_endpoint IS NULL AND confirmation_idempotency_key IS NULL AND confirmation_request_hash IS NULL AND confirmation_candidate_hash IS NULL AND confirmation_cutoff_at IS NULL AND confirmation_config_version IS NULL AND confirmation_prune_run_row_version IS NULL AND confirmation_issued_at IS NULL AND confirmation_expires_at IS NULL AND confirmation_consumed_at IS NULL)
    OR (
      confirmation_status IN ('issued', 'consumed', 'expired')
      AND confirmation_id IS NOT NULL AND confirmation_id REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      AND confirmation_actor_id IS NOT NULL AND confirmation_actor_id REGEXP '^[0-9]+$'
      AND confirmation_endpoint = 'issueSystemBackupPruneConfirmation'
      AND confirmation_idempotency_key IS NOT NULL AND confirmation_idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$'
      AND confirmation_request_hash IS NOT NULL AND confirmation_request_hash REGEXP '^[0-9a-f]{64}$'
      AND confirmation_candidate_hash IS NOT NULL
      AND confirmation_candidate_hash = candidate_hash
      AND confirmation_cutoff_at IS NOT NULL
      AND confirmation_cutoff_at = older_than
      AND confirmation_config_version IS NOT NULL
      AND confirmation_config_version = config_version
      AND confirmation_prune_run_row_version IS NOT NULL
      AND confirmation_prune_run_row_version BETWEEN 1 AND row_version
      AND confirmation_issued_at IS NOT NULL
      AND confirmation_issued_at >= started_at
      AND confirmation_expires_at IS NOT NULL
      AND confirmation_expires_at > confirmation_issued_at
      AND confirmation_expires_at <= candidate_expires_at
      AND ((confirmation_status = 'consumed' AND confirmation_consumed_at BETWEEN confirmation_issued_at AND confirmation_expires_at) OR (confirmation_status IN ('issued', 'expired') AND confirmation_consumed_at IS NULL))
    )
  ),
  CONSTRAINT chk_sb_prune_run_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_prune_run_retry CHECK (
    retryable = FALSE
    OR (status IN ('partial_failed', 'failed') AND failure_category IN ('deadline_exceeded', 'catalog_tombstone_failed', 'artifact_delete_failed'))
  ),
  CONSTRAINT chk_sb_prune_run_status CHECK (
    (status = 'planning' AND retryable = FALSE AND failure_category = 'none' AND confirmation_status = 'none' AND execution_count = 0 AND last_operation_public_id IS NULL AND execution_started_at IS NULL AND execution_finished_at IS NULL AND finished_at IS NULL)
    OR (status = 'dry_run_created' AND retryable = FALSE AND failure_category = 'none' AND confirmation_status IN ('none', 'issued', 'expired') AND execution_count = 0 AND last_operation_public_id IS NULL AND execution_started_at IS NULL AND execution_finished_at IS NULL AND finished_at IS NULL)
    OR (status = 'executing' AND retryable = FALSE AND failure_category = 'none' AND confirmation_status = 'consumed' AND execution_count >= 1 AND last_operation_public_id IS NOT NULL AND execution_started_at IS NOT NULL AND execution_finished_at IS NULL AND finished_at IS NULL)
    OR (status = 'partial_failed' AND retryable = TRUE AND failure_category IN ('deadline_exceeded', 'catalog_tombstone_failed', 'artifact_delete_failed') AND confirmation_status = 'consumed' AND execution_count >= 1 AND last_operation_public_id IS NOT NULL AND execution_started_at IS NOT NULL AND execution_finished_at IS NOT NULL AND finished_at IS NULL)
    OR (status = 'succeeded' AND retryable = FALSE AND failure_category = 'none' AND confirmation_status = 'consumed' AND execution_count >= 1 AND last_operation_public_id IS NOT NULL AND execution_started_at IS NOT NULL AND execution_finished_at IS NOT NULL AND finished_at IS NOT NULL)
    OR (status = 'failed' AND failure_category NOT IN ('none', 'canceled_by_actor', 'canceled_by_shutdown') AND ((execution_count = 0 AND last_operation_public_id IS NULL AND execution_started_at IS NULL AND execution_finished_at IS NULL AND confirmation_status IN ('none', 'issued', 'expired')) OR (execution_count >= 1 AND last_operation_public_id IS NOT NULL AND execution_started_at IS NOT NULL AND execution_finished_at IS NOT NULL AND confirmation_status = 'consumed')) AND ((retryable = TRUE AND finished_at IS NULL) OR (retryable = FALSE AND finished_at IS NOT NULL)))
    OR (status = 'expired' AND retryable = FALSE AND failure_category = 'none' AND confirmation_status IN ('none', 'expired') AND execution_count = 0 AND last_operation_public_id IS NULL AND execution_started_at IS NULL AND execution_finished_at IS NULL AND finished_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_prune_run_times CHECK (
    row_version >= 1 AND older_than < started_at AND started_at >= created_at AND updated_at >= created_at
    AND (execution_started_at IS NULL OR execution_started_at >= started_at)
    AND (execution_finished_at IS NULL OR execution_finished_at >= execution_started_at)
    AND (finished_at IS NULL OR finished_at >= started_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_prune_items (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-prune-item.v1',
  public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  prune_run_id BIGINT UNSIGNED NOT NULL,
  artifact_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  item_type ENUM('object_version', 'delete_marker', 'catalog_tombstone') NOT NULL,
  status ENUM('planned', 'blocked_by_delete', 'deleting', 'deleted', 'delete_failed') NOT NULL,
  canonical_location_key VARBINARY(4096) NULL,
  canonical_location_size_bytes INT UNSIGNED NULL,
  canonical_location_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  immutable_version VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  immutable_version_sentinel VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (COALESCE(immutable_version, '<catalog-tombstone>')) STORED,
  catalog_record_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_registration_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  artifact_registration_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
  artifact_plan_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  planned_backup_status ENUM('succeeded', 'failed', 'canceled') NOT NULL,
  planned_backup_finished_at DATETIME(6) NOT NULL,
  planned_artifact_state ENUM('committed', 'corrupt') NOT NULL,
  planned_prune_guard_version BIGINT UNSIGNED NOT NULL,
  last_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  attempt INT UNSIGNED NOT NULL DEFAULT 0,
  item_failure_code ENUM('none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch', 'checksum_mismatch', 'catalog_conflict', 'internal') NOT NULL DEFAULT 'none',
  external_action_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  controller_lease_expires_at DATETIME(6) NULL,
  next_reconcile_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  delete_started_at DATETIME(6) NULL,
  deleted_at DATETIME(6) NULL,
  delete_failed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_prune_item_public (public_id),
  UNIQUE KEY uk_sb_prune_item_origin_public (origin_installation_id, public_id),
  UNIQUE KEY uk_sb_prune_item_plan (prune_run_id, artifact_public_id, item_type, canonical_location_hash, immutable_version_sentinel),
  KEY idx_sb_prune_item_cursor (prune_run_id, created_at, id),
  KEY idx_sb_prune_item_status (prune_run_id, status, next_reconcile_at, id),
  KEY idx_sb_prune_item_artifact (origin_installation_id, artifact_public_id, status),
  KEY idx_sb_prune_item_operation (last_operation_public_id),
  CONSTRAINT fk_sb_prune_item_run FOREIGN KEY (origin_installation_id, prune_run_id) REFERENCES system_backup_prune_runs(origin_installation_id, id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_prune_item_backup FOREIGN KEY (origin_installation_id, artifact_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_prune_item_registration FOREIGN KEY (origin_installation_id, artifact_public_id, artifact_registration_id, artifact_registration_hash) REFERENCES system_backups(origin_installation_id, public_id, artifact_registration_id, artifact_registration_hash) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_prune_item_operation FOREIGN KEY (last_operation_public_id) REFERENCES system_backup_operations(public_id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_prune_item_identity CHECK (
    schema_version = 'system-backup-prune-item.v1'
    AND public_id REGEXP '^spi_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND artifact_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  ),
  CONSTRAINT chk_sb_prune_item_plan_hashes CHECK (
    canonical_location_hash REGEXP '^[0-9a-f]{64}$'
    AND artifact_plan_hash REGEXP '^[0-9a-f]{64}$'
    AND planned_prune_guard_version >= 1
  ),
  CONSTRAINT chk_sb_prune_item_location CHECK (
    (item_type IN ('object_version', 'delete_marker') AND canonical_location_key IS NOT NULL AND canonical_location_size_bytes BETWEEN 1 AND 4096 AND canonical_location_size_bytes = OCTET_LENGTH(canonical_location_key) AND canonical_location_hash = SHA2(canonical_location_key, 256))
    OR (item_type = 'catalog_tombstone' AND canonical_location_key IS NULL AND canonical_location_size_bytes IS NULL)
  ),
  CONSTRAINT chk_sb_prune_item_kind CHECK (
    (item_type IN ('object_version', 'delete_marker') AND immutable_version IS NOT NULL AND CHAR_LENGTH(immutable_version) BETWEEN 1 AND 256 AND catalog_record_hash IS NULL AND artifact_registration_id IS NULL AND artifact_registration_hash IS NULL AND external_action_public_id IS NULL)
    OR (item_type = 'catalog_tombstone' AND immutable_version IS NULL AND catalog_record_hash IS NOT NULL AND catalog_record_hash REGEXP '^[0-9a-f]{64}$' AND artifact_registration_id IS NOT NULL AND CHAR_LENGTH(artifact_registration_id) BETWEEN 1 AND 128 AND artifact_registration_hash IS NOT NULL AND artifact_registration_hash = catalog_record_hash AND bytes = 0 AND ((status = 'blocked_by_delete' AND external_action_public_id IS NULL) OR (status <> 'blocked_by_delete' AND external_action_public_id IS NOT NULL AND external_action_public_id REGEXP '^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')))
  ),
  CONSTRAINT chk_sb_prune_item_blocked CHECK (status <> 'blocked_by_delete' OR item_type = 'catalog_tombstone'),
  CONSTRAINT chk_sb_prune_item_claim CHECK ((controller_owner IS NULL AND controller_lease_expires_at IS NULL) OR (controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL)),
  CONSTRAINT chk_sb_prune_item_status CHECK (
    (status = 'blocked_by_delete' AND attempt = 0 AND item_failure_code = 'none' AND last_operation_public_id IS NULL AND controller_owner IS NULL AND controller_lease_expires_at IS NULL AND delete_started_at IS NULL AND deleted_at IS NULL AND delete_failed_at IS NULL)
    OR (status = 'planned' AND item_failure_code = 'none' AND controller_owner IS NULL AND controller_lease_expires_at IS NULL AND delete_started_at IS NULL AND deleted_at IS NULL AND delete_failed_at IS NULL AND ((attempt = 0 AND last_operation_public_id IS NULL) OR (attempt >= 1 AND last_operation_public_id IS NOT NULL)))
    OR (status = 'deleting' AND attempt >= 1 AND item_failure_code = 'none' AND last_operation_public_id IS NOT NULL AND controller_owner IS NOT NULL AND controller_lease_expires_at IS NOT NULL AND delete_started_at IS NOT NULL AND deleted_at IS NULL)
    OR (status = 'deleted' AND attempt >= 1 AND item_failure_code = 'none' AND last_operation_public_id IS NOT NULL AND controller_owner IS NULL AND controller_lease_expires_at IS NULL AND delete_started_at IS NOT NULL AND deleted_at IS NOT NULL)
    OR (status = 'delete_failed' AND attempt >= 1 AND item_failure_code <> 'none' AND last_operation_public_id IS NOT NULL AND controller_owner IS NULL AND controller_lease_expires_at IS NULL AND delete_failed_at IS NOT NULL AND deleted_at IS NULL)
  ),
  CONSTRAINT chk_sb_prune_item_times CHECK (
    row_version >= 1 AND planned_backup_finished_at <= created_at AND updated_at >= created_at
    AND (delete_started_at IS NULL OR delete_started_at >= created_at)
    AND (deleted_at IS NULL OR deleted_at >= delete_started_at)
    AND (delete_failed_at IS NULL OR delete_failed_at >= COALESCE(delete_started_at, created_at))
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
