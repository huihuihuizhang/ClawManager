-- D-only candidate. Not a numbered migration or an installed schema.
-- Review schema ownership, exact grants and current catalog before promotion.
CREATE TABLE system_backup_control_health (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-control-health.v1',
  config_version BIGINT UNSIGNED NOT NULL,
  writer_epoch BIGINT UNSIGNED NOT NULL,
  writer_owner VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observation_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  controller_health ENUM('healthy','degraded','unknown') NOT NULL,
  database_health ENUM('healthy','degraded','unknown') NOT NULL,
  observed_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (origin_installation_id),
  CONSTRAINT fk_sb_control_health_installation FOREIGN KEY (origin_installation_id)
    REFERENCES system_backup_installation_state(origin_installation_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_control_health_config FOREIGN KEY (origin_installation_id,config_version)
    REFERENCES system_backup_configs(origin_installation_id,version) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_control_health_schema CHECK (schema_version='system-backup-control-health.v1'),
  CONSTRAINT chk_sb_control_health_versions CHECK (config_version BETWEEN 1 AND 9007199254740991
    AND writer_epoch BETWEEN 1 AND 9007199254740991 AND observation_sequence<=9007199254740991),
  CONSTRAINT chk_sb_control_health_owner CHECK (writer_owner REGEXP '^[A-Za-z0-9._:-]{1,128}$'),
  CONSTRAINT chk_sb_control_health_states CHECK (
    (observation_sequence=0 AND controller_health='unknown' AND database_health='unknown')
    OR (observation_sequence>0 AND controller_health IN ('healthy','degraded') AND database_health IN ('healthy','degraded'))),
  CONSTRAINT chk_sb_control_health_time CHECK (expires_at>observed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
