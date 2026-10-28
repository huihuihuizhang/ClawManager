-- Integration-reviewed isolated control schema. No production activation or grants.

CREATE TABLE IF NOT EXISTS system_backup_v2_config_maintenance_receipts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
    DEFAULT 'system-backup-config-maintenance-receipt.v1',
  receipt_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_server_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_database VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  maintenance_actor_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  action ENUM('config_canonical_backfill') NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_identity_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_version BIGINT UNSIGNED NOT NULL,
  original_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  original_config_size_bytes INT UNSIGNED NOT NULL,
  expected_row_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_provenance_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  schema_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  catalog_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  migration_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  wrote BOOLEAN NOT NULL,
  intent_audit_id INT NOT NULL,
  result_audit_id INT NOT NULL,
  redacted_response_canonical_json MEDIUMBLOB NOT NULL,
  redacted_response_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  redacted_response_size_bytes INT UNSIGNED NOT NULL,
  created_at DATETIME(6) NOT NULL,
  UNIQUE KEY uk_d_cfg_maintenance_receipt (receipt_id),
  UNIQUE KEY uk_d_cfg_maintenance_idempotency
    (target_server_uuid,target_database,origin_installation_id,maintenance_actor_sha256,action,idempotency_key),
  KEY idx_d_cfg_maintenance_target (origin_installation_id,config_version,id),
  CONSTRAINT sbv2_fk_d_cfg_maintenance_config FOREIGN KEY (origin_installation_id,config_version)
    REFERENCES system_backup_v2_configs(origin_installation_id,version) ON DELETE RESTRICT,
  CONSTRAINT sbv2_fk_d_cfg_maintenance_intent FOREIGN KEY (intent_audit_id)
    REFERENCES audit_logs(id) ON DELETE RESTRICT,
  CONSTRAINT sbv2_fk_d_cfg_maintenance_result FOREIGN KEY (result_audit_id)
    REFERENCES audit_logs(id) ON DELETE RESTRICT,
  CONSTRAINT sbv2_chk_d_cfg_maintenance_schema CHECK (
    schema_version='system-backup-config-maintenance-receipt.v1'
  ),
  CONSTRAINT sbv2_chk_d_cfg_maintenance_scope CHECK (
    receipt_id REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND target_server_uuid REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND target_database REGEXP '^[A-Za-z0-9_]{1,64}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$'
    AND grant_version REGEXP '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT sbv2_chk_d_cfg_maintenance_digests CHECK (
    maintenance_actor_sha256 REGEXP '^[0-9a-f]{64}$'
    AND request_sha256 REGEXP '^[0-9a-f]{64}$'
    AND grant_identity_sha256 REGEXP '^[0-9a-f]{64}$'
    AND original_config_sha256 REGEXP '^[0-9a-f]{64}$'
    AND expected_row_sha256 REGEXP '^[0-9a-f]{64}$'
    AND source_provenance_sha256 REGEXP '^[0-9a-f]{64}$'
    AND schema_sha256 REGEXP '^[0-9a-f]{64}$'
    AND catalog_sha256 REGEXP '^[0-9a-f]{64}$'
    AND migration_sha256 REGEXP '^[0-9a-f]{64}$'
    AND redacted_response_sha256 REGEXP '^[0-9a-f]{64}$'
  ),
  CONSTRAINT sbv2_chk_d_cfg_maintenance_result CHECK (
    config_version BETWEEN 1 AND 9007199254740991
    AND original_config_size_bytes BETWEEN 2 AND 262144
    AND wrote IN (0,1)
    AND intent_audit_id>0 AND result_audit_id>0 AND intent_audit_id<>result_audit_id
  ),
  CONSTRAINT sbv2_chk_d_cfg_maintenance_response CHECK (
    redacted_response_size_bytes BETWEEN 2 AND 65536
    AND OCTET_LENGTH(redacted_response_canonical_json)=redacted_response_size_bytes
    AND JSON_VALID(CONVERT(redacted_response_canonical_json USING utf8mb4))
    AND JSON_TYPE(CONVERT(redacted_response_canonical_json USING utf8mb4))='OBJECT'
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
