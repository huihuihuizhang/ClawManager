-- Integration-reviewed isolated control schema. No production activation or grants.

CREATE TABLE IF NOT EXISTS system_backup_v2_recovery_deployments (
  scope_key BINARY(32) NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  workload_identity_hash BINARY(32) NOT NULL,
  issuer_identity_hash BINARY(32) NOT NULL,
  subject_hash BINARY(32) NOT NULL,
  management_issuer_identity_hash BINARY(32) NOT NULL,
  actor_identity_hash BINARY(32) NOT NULL,
  admission_hash BINARY(32) NOT NULL,
  client_ca_sha256 BINARY(32) NOT NULL,
  certificate_sha256 BINARY(32) NOT NULL,
  stat_profile_hash BINARY(32) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  deployment_epoch BIGINT UNSIGNED NOT NULL,
  authorized_until DATETIME(6) NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (scope_key),
  KEY ix_sb_recovery_deployment_installation (origin_installation_id),
  CONSTRAINT sbv2_fk_sb_recovery_deployment_installation
    FOREIGN KEY (origin_installation_id)
    REFERENCES system_backup_v2_installation_state (origin_installation_id)
    ON DELETE RESTRICT,
  CONSTRAINT sbv2_ck_sb_recovery_deployment_epoch CHECK (deployment_epoch > 0),
  CONSTRAINT sbv2_ck_sb_recovery_deployment_version CHECK (row_version > 0)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

CREATE TABLE IF NOT EXISTS system_backup_v2_recovery_managers (
  scope_key BINARY(32) NOT NULL,
  management_identity_hash BINARY(32) NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  issuer_identity_hash BINARY(32) NOT NULL,
  credential_binding_hash BINARY(32) NOT NULL,
  can_read_fence BOOLEAN NOT NULL DEFAULT FALSE,
  can_write_fence BOOLEAN NOT NULL DEFAULT FALSE,
  can_manage_deployment BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  authorized_until DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (scope_key, management_identity_hash),
  KEY ix_sb_recovery_manager_installation (origin_installation_id),
  CONSTRAINT sbv2_fk_sb_recovery_manager_installation
    FOREIGN KEY (origin_installation_id)
    REFERENCES system_backup_v2_installation_state (origin_installation_id)
    ON DELETE RESTRICT,
  CONSTRAINT sbv2_ck_sb_recovery_manager_version CHECK (row_version > 0),
  CONSTRAINT sbv2_ck_sb_recovery_manager_enabled
    CHECK (enabled = FALSE OR revoked_at IS NULL)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;
