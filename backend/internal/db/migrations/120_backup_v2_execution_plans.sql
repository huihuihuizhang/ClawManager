-- The execution plan is immutable and encrypted before any Job is sent.
-- It belongs to the public v2 task; no legacy shadow task is created.
CREATE TABLE IF NOT EXISTS system_backup_v2_execution_plans (
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  schema_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  profile_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  plan_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  key_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  nonce VARBINARY(12) NOT NULL,
  ciphertext MEDIUMBLOB NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY(origin_installation_id,task_public_id),
  CONSTRAINT sbv2_fk_execution_plan_input FOREIGN KEY(origin_installation_id,task_public_id)
    REFERENCES system_backup_v2_execution_inputs(origin_installation_id,task_public_id) ON DELETE RESTRICT,
  CONSTRAINT sbv2_chk_execution_plan_hash CHECK(profile_sha256 REGEXP '^[0-9a-f]{64}$' AND config_sha256 REGEXP '^[0-9a-f]{64}$' AND plan_sha256 REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT sbv2_chk_execution_plan_version CHECK(schema_version REGEXP '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND key_version REGEXP '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  CONSTRAINT sbv2_chk_execution_plan_cipher CHECK(OCTET_LENGTH(nonce)=12 AND OCTET_LENGTH(ciphertext) BETWEEN 18 AND 65552)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
