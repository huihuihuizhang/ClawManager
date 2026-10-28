CREATE TABLE IF NOT EXISTS system_backup_v2_installation_state (
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
  CONSTRAINT sbv2_chk_sb_installation_schema CHECK (schema_version = 'system-backup-installation-state.v1'),
  CONSTRAINT sbv2_chk_sb_installation_config_version CHECK (active_config_version >= 1),
  CONSTRAINT sbv2_chk_sb_installation_row_version CHECK (row_version >= 1),
  CONSTRAINT sbv2_chk_sb_installation_operation_id CHECK (matrix_transition_operation_public_id IS NULL OR matrix_transition_operation_public_id REGEXP '^sop_'),
  CONSTRAINT sbv2_chk_sb_installation_monitoring CHECK (
    (monitoring_armed = FALSE AND monitoring_armed_reason = 'none' AND first_enabled_at IS NULL)
    OR (monitoring_armed = TRUE AND monitoring_armed_reason = 'deployment_required')
    OR (monitoring_armed = TRUE AND monitoring_armed_reason = 'previously_enabled' AND first_enabled_at IS NOT NULL)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
