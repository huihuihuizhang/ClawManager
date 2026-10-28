-- Integration-reviewed isolated control schema. No production activation or grants.

CREATE TABLE IF NOT EXISTS system_backup_v2_producer_recovery_revocations (
  scope_key BINARY(32) NOT NULL,
  workload_identity_hash BINARY(32) NOT NULL,
  revocation_epoch BIGINT UNSIGNED NOT NULL,
  revoked_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_key, workload_identity_hash),
  CONSTRAINT sbv2_ck_prod_recovery_revocation_epoch CHECK (revocation_epoch > 0),
  CONSTRAINT sbv2_ck_prod_recovery_revocation_version CHECK (row_version > 0)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;
