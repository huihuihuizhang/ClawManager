CREATE TABLE IF NOT EXISTS system_backup_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-event.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_type ENUM('backup', 'drill', 'preflight', 'artifact_verify', 'catalog_import', 'promotion', 'cleanup', 'prune_run', 'catalog_scan', 'catalog_record', 'operation', 'system') NOT NULL,
  target_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  event_type VARCHAR(160) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  level ENUM('info', 'warning', 'error', 'critical') NOT NULL,
  task_status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
  message VARCHAR(2048) NOT NULL,
  details_present BOOLEAN NOT NULL DEFAULT FALSE,
  detail_previous_status VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  detail_current_status VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  detail_reason VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  detail_attempt_number INT UNSIGNED NULL,
  detail_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  detail_evidence_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
  detail_truncated BOOLEAN NULL,
  detail_original_size BIGINT UNSIGNED NULL,
  detail_content_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY idx_sb_event_cursor (target_type, target_public_id, created_at, id),
  KEY idx_sb_event_installation (origin_installation_id, created_at, id),
  KEY idx_sb_event_type (event_type, created_at, id),
  CONSTRAINT chk_sb_event_schema CHECK (schema_version = 'system-backup-event.v1'),
  CONSTRAINT chk_sb_event_origin CHECK (origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'),
  CONSTRAINT chk_sb_event_target CHECK (
    (target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'drill' AND target_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'preflight' AND target_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'artifact_verify' AND target_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_import' AND target_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'promotion' AND target_public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type IN ('cleanup', 'operation') AND target_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'prune_run' AND target_public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_scan' AND target_public_id REGEXP '^scs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_record' AND target_public_id REGEXP '^scr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'system' AND target_public_id = origin_installation_id)
  ),
  CONSTRAINT chk_sb_event_type CHECK (
    event_type IN ('task_status_changed', 'attempt_started', 'attempt_finished', 'gate_changed', 'participant_changed', 'artifact_committed', 'artifact_health_changed', 'external_action_changed', 'evidence_changed', 'log_persistence_changed', 'provider_capability_changed', 'dependency_health_changed', 'catalog_scan_changed', 'catalog_record_changed', 'cleanup_changed', 'ownership_resolved', 'prune_changed', 'promotion_changed', 'operation_finished')
    OR event_type REGEXP '^diagnostic\\.[a-d]\\.[a-z0-9_-]{1,64}$'
  ),
  CONSTRAINT chk_sb_event_task_status CHECK (
    (target_type = 'backup' AND (task_status IS NULL OR task_status IN ('pending', 'preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'validating', 'publishing', 'finalization_unknown', 'canceling', 'succeeded', 'failed', 'canceled')))
    OR (target_type = 'drill' AND (task_status IS NULL OR task_status IN ('pending', 'preflighting', 'provisioning', 'restoring', 'normalizing', 'verifying', 'canceling', 'succeeded', 'failed', 'canceled')))
    OR (target_type IN ('preflight', 'artifact_verify') AND (task_status IS NULL OR task_status IN ('pending', 'running', 'canceling', 'succeeded', 'failed', 'canceled')))
    OR (target_type NOT IN ('backup', 'drill', 'preflight', 'artifact_verify') AND task_status IS NULL)
  ),
  CONSTRAINT chk_sb_event_details CHECK (
    (details_present = FALSE AND detail_previous_status IS NULL AND detail_current_status IS NULL AND detail_reason IS NULL AND detail_attempt_number IS NULL AND detail_operation_public_id IS NULL AND detail_evidence_public_id IS NULL AND detail_truncated IS NULL AND detail_original_size IS NULL AND detail_content_hash IS NULL)
    OR (details_present = TRUE
      AND (detail_reason IS NULL OR detail_reason REGEXP '^[a-z][a-z0-9_]*$')
      AND (detail_attempt_number IS NULL OR detail_attempt_number >= 1)
      AND (detail_operation_public_id IS NULL OR detail_operation_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
      AND (detail_evidence_public_id IS NULL OR detail_evidence_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
      AND ((detail_truncated = TRUE AND detail_original_size IS NOT NULL AND detail_content_hash REGEXP '^[0-9a-f]{64}$') OR ((detail_truncated IS NULL OR detail_truncated = FALSE) AND detail_original_size IS NULL AND detail_content_hash IS NULL)))
  ),
  CONSTRAINT chk_sb_event_request CHECK (request_id IS NULL OR request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_alert_states (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  rule_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  matrix_key ENUM('all', 'k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node') NOT NULL DEFAULT 'all',
  task_type ENUM('all', 'backup', 'drill', 'preflight', 'artifact_verify') NOT NULL DEFAULT 'all',
  task_purpose ENUM('all', 'acceptance', 'functional_test') NOT NULL DEFAULT 'all',
  consecutive_anomaly_count INT UNSIGNED NOT NULL DEFAULT 0,
  first_anomaly_at DATETIME(6) NULL,
  last_observed_at DATETIME(6) NULL,
  last_eligible_success_at DATETIME(6) NULL,
  alert_state ENUM('firing', 'resolved') NOT NULL DEFAULT 'resolved',
  condition_true_since_at DATETIME(6) NULL,
  fired_at DATETIME(6) NULL,
  resolved_at DATETIME(6) NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_alert_scope (origin_installation_id, rule_key, matrix_key, task_type, task_purpose),
  KEY idx_sb_alert_state (origin_installation_id, alert_state, updated_at, id),
  CONSTRAINT fk_sb_alert_config FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_alert_origin CHECK (origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'),
  CONSTRAINT chk_sb_alert_rule CHECK (rule_key REGEXP '^[a-z][a-z0-9_.-]{0,127}$'),
  CONSTRAINT chk_sb_alert_dimensions CHECK (task_purpose = 'all' OR task_type IN ('backup', 'drill')),
  CONSTRAINT chk_sb_alert_sequence CHECK (
    (consecutive_anomaly_count = 0 AND first_anomaly_at IS NULL)
    OR (consecutive_anomaly_count > 0 AND first_anomaly_at IS NOT NULL AND last_observed_at IS NOT NULL AND last_observed_at >= first_anomaly_at)
  ),
  CONSTRAINT chk_sb_alert_success_time CHECK (last_eligible_success_at IS NULL OR (last_observed_at IS NOT NULL AND last_eligible_success_at <= last_observed_at)),
  CONSTRAINT chk_sb_alert_lifecycle CHECK (
    (alert_state = 'firing' AND condition_true_since_at IS NOT NULL AND fired_at IS NOT NULL AND resolved_at IS NULL AND fired_at >= condition_true_since_at)
    OR (alert_state = 'resolved' AND condition_true_since_at IS NULL AND ((fired_at IS NULL AND resolved_at IS NULL) OR (fired_at IS NOT NULL AND resolved_at IS NOT NULL AND resolved_at >= fired_at)))
  ),
  CONSTRAINT chk_sb_alert_times CHECK (row_version >= 1 AND updated_at >= created_at AND (last_observed_at IS NULL OR last_observed_at >= created_at))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_artifact_lease_states (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_artifact_type ENUM('backup', 'catalog_import') NOT NULL,
  source_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lease_mode ENUM('shared', 'delete') NOT NULL DEFAULT 'shared',
  generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_artifact_lease_source (origin_installation_id, source_artifact_type, source_public_id),
  UNIQUE KEY uk_sb_artifact_lease_mode (origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode),
  CONSTRAINT chk_sb_artifact_lease_state_origin CHECK (origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'),
  CONSTRAINT chk_sb_artifact_lease_state_source CHECK (
    (source_artifact_type = 'backup' AND source_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (source_artifact_type = 'catalog_import' AND source_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_artifact_lease_state_version CHECK (generation >= 1 AND row_version >= 1 AND updated_at >= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_artifact_leases (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_artifact_type ENUM('backup', 'catalog_import') NOT NULL,
  source_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lease_generation BIGINT UNSIGNED NOT NULL,
  lease_mode ENUM('shared', 'delete') NOT NULL,
  holder_type ENUM('drill', 'preflight', 'artifact_verify', 'health_reconcile', 'prune') NOT NULL,
  holder_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  purpose ENUM('read', 'verify', 'delete') NOT NULL,
  lease_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  lease_ttl_seconds INT UNSIGNED NOT NULL,
  heartbeat_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  delete_source_guard VARCHAR(170) CHARACTER SET ascii COLLATE ascii_bin GENERATED ALWAYS AS (CASE WHEN purpose = 'delete' THEN CONCAT(source_artifact_type, ':', source_public_id) ELSE NULL END) STORED,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_artifact_lease_holder (origin_installation_id, source_artifact_type, source_public_id, holder_type, holder_public_id),
  UNIQUE KEY uk_sb_artifact_delete_guard (origin_installation_id, delete_source_guard),
  KEY idx_sb_artifact_lease_state (origin_installation_id, source_artifact_type, source_public_id, lease_generation, lease_mode),
  KEY idx_sb_artifact_lease_expiry (source_artifact_type, source_public_id, expires_at, id),
  KEY idx_sb_artifact_lease_owner (lease_owner, expires_at, id),
  CONSTRAINT fk_sb_artifact_lease_config FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_artifact_lease_state FOREIGN KEY (origin_installation_id, source_artifact_type, source_public_id, lease_generation, lease_mode) REFERENCES system_artifact_lease_states(origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT chk_sb_artifact_lease_origin CHECK (origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'),
  CONSTRAINT chk_sb_artifact_lease_source CHECK (
    (source_artifact_type = 'backup' AND source_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (source_artifact_type = 'catalog_import' AND source_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  CONSTRAINT chk_sb_artifact_lease_holder CHECK (
    (holder_type = 'drill' AND holder_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND purpose = 'read' AND lease_mode = 'shared')
    OR (holder_type = 'preflight' AND holder_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND purpose = 'read' AND lease_mode = 'shared')
    OR (holder_type = 'artifact_verify' AND holder_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND purpose = 'verify' AND lease_mode = 'shared')
    OR (holder_type = 'health_reconcile' AND holder_public_id REGEXP '^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND purpose = 'verify' AND lease_mode = 'shared')
    OR (holder_type = 'prune' AND holder_public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND purpose = 'delete' AND lease_mode = 'delete' AND source_artifact_type = 'backup')
  ),
  CONSTRAINT chk_sb_artifact_lease_time CHECK (
    lease_generation >= 1 AND lease_ttl_seconds BETWEEN 15 AND 300 AND row_version >= 1
    AND heartbeat_at >= created_at AND expires_at > heartbeat_at
    AND TIMESTAMPDIFF(MICROSECOND, heartbeat_at, expires_at) <= lease_ttl_seconds * 1000000
    AND updated_at >= created_at
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_maintenance_locks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lock_name ENUM('system_backup_capture_gate') NOT NULL DEFAULT 'system_backup_capture_gate',
  scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gate_state ENUM('idle', 'acquiring', 'held', 'releasing') NOT NULL DEFAULT 'idle',
  generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
  fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
  lock_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  heartbeat_at DATETIME(6) NULL,
  lock_ttl_seconds INT UNSIGNED NOT NULL,
  lease_expires_at DATETIME(6) NULL,
  gate_acquisition_timeout_seconds INT UNSIGNED NULL,
  quiesce_max_hold_seconds INT UNSIGNED NULL,
  acquiring_started_at DATETIME(6) NULL,
  held_at DATETIME(6) NULL,
  release_started_at DATETIME(6) NULL,
  acquisition_deadline_at DATETIME(6) NULL,
  absolute_hold_deadline_at DATETIME(6) NULL,
  state_changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_maintenance_gate (origin_installation_id, scope),
  KEY idx_sb_maintenance_gate_state (gate_state, lease_expires_at, id),
  CONSTRAINT chk_sb_maintenance_origin CHECK (origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'),
  CONSTRAINT chk_sb_maintenance_scope CHECK (scope REGEXP '^[A-Za-z0-9._:-]{1,128}$'),
  CONSTRAINT chk_sb_maintenance_idle CHECK (
    (gate_state = 'idle' AND lock_owner IS NULL AND heartbeat_at IS NULL AND lease_expires_at IS NULL AND gate_acquisition_timeout_seconds IS NULL AND quiesce_max_hold_seconds IS NULL AND acquiring_started_at IS NULL AND held_at IS NULL AND release_started_at IS NULL AND acquisition_deadline_at IS NULL AND absolute_hold_deadline_at IS NULL)
    OR (gate_state = 'acquiring' AND lock_owner IS NOT NULL AND heartbeat_at IS NOT NULL AND lease_expires_at IS NOT NULL AND gate_acquisition_timeout_seconds BETWEEN 10 AND 600 AND quiesce_max_hold_seconds IS NULL AND acquiring_started_at IS NOT NULL AND held_at IS NULL AND release_started_at IS NULL AND acquisition_deadline_at IS NOT NULL AND absolute_hold_deadline_at IS NULL AND acquisition_deadline_at > heartbeat_at AND TIMESTAMPDIFF(MICROSECOND, acquiring_started_at, acquisition_deadline_at) <= gate_acquisition_timeout_seconds * 1000000)
    OR (gate_state = 'held' AND lock_owner IS NOT NULL AND heartbeat_at IS NOT NULL AND lease_expires_at IS NOT NULL AND gate_acquisition_timeout_seconds BETWEEN 10 AND 600 AND quiesce_max_hold_seconds BETWEEN 30 AND 3600 AND acquiring_started_at IS NOT NULL AND held_at IS NOT NULL AND held_at >= acquiring_started_at AND release_started_at IS NULL AND acquisition_deadline_at IS NOT NULL AND absolute_hold_deadline_at IS NOT NULL AND absolute_hold_deadline_at > heartbeat_at AND TIMESTAMPDIFF(MICROSECOND, held_at, absolute_hold_deadline_at) <= quiesce_max_hold_seconds * 1000000)
    OR (gate_state = 'releasing' AND lock_owner IS NOT NULL AND heartbeat_at IS NOT NULL AND lease_expires_at IS NOT NULL AND gate_acquisition_timeout_seconds BETWEEN 10 AND 600 AND quiesce_max_hold_seconds BETWEEN 30 AND 3600 AND acquiring_started_at IS NOT NULL AND held_at IS NOT NULL AND held_at >= acquiring_started_at AND release_started_at IS NOT NULL AND release_started_at >= held_at AND acquisition_deadline_at IS NOT NULL AND absolute_hold_deadline_at IS NOT NULL AND absolute_hold_deadline_at > held_at AND TIMESTAMPDIFF(MICROSECOND, held_at, absolute_hold_deadline_at) <= quiesce_max_hold_seconds * 1000000)
  ),
  CONSTRAINT chk_sb_maintenance_fence CHECK ((gate_state IN ('held', 'releasing') AND fencing_token >= 1) OR (gate_state IN ('idle', 'acquiring'))),
  CONSTRAINT chk_sb_maintenance_time CHECK (
    generation >= 1 AND row_version >= 1 AND lock_ttl_seconds BETWEEN 65 AND 7200
    AND state_changed_at >= created_at AND updated_at >= created_at
    AND (heartbeat_at IS NULL OR (heartbeat_at >= created_at AND lease_expires_at > heartbeat_at AND TIMESTAMPDIFF(MICROSECOND, heartbeat_at, lease_expires_at) <= lock_ttl_seconds * 1000000))
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_maintenance_mutation_leases (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  lease_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  operation_identity VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lease_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gate_generation BIGINT UNSIGNED NOT NULL,
  lease_ttl_seconds INT UNSIGNED NOT NULL,
  heartbeat_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_mutation_lease_id (lease_id),
  KEY idx_sb_mutation_scope (origin_installation_id, scope, gate_generation, expires_at, id),
  KEY idx_sb_mutation_owner (lease_owner, expires_at, id),
  CONSTRAINT fk_sb_mutation_gate FOREIGN KEY (origin_installation_id, scope) REFERENCES system_maintenance_locks(origin_installation_id, scope) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_mutation_identity CHECK (
    lease_id REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND scope REGEXP '^[A-Za-z0-9._:-]{1,128}$'
    AND operation_identity REGEXP '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'
    AND request_id REGEXP '^[A-Za-z0-9._:-]{1,128}$'
  ),
  CONSTRAINT chk_sb_mutation_time CHECK (
    gate_generation >= 1 AND lease_ttl_seconds BETWEEN 6 AND 120 AND row_version >= 1
    AND heartbeat_at >= created_at AND expires_at > heartbeat_at
    AND TIMESTAMPDIFF(MICROSECOND, heartbeat_at, expires_at) <= lease_ttl_seconds * 1000000
    AND updated_at >= created_at
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
