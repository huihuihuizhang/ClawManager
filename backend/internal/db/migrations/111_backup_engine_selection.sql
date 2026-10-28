-- Integration-owned engine choice. Creating the row never enables a new engine.
CREATE TABLE IF NOT EXISTS system_backup_v2_engine_bindings (
  scope VARCHAR(128) NOT NULL PRIMARY KEY,
  engine VARCHAR(16) NOT NULL DEFAULT 'legacy',
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT sbv2_engine_choice CHECK (engine IN ('legacy','v2')),
  CONSTRAINT sbv2_engine_version CHECK (row_version >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
