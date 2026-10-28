-- C1 candidate only. A and C review is required before a numbered migration.
-- L2 current workload revocation is independent of the original producer
-- domain, grant, administrator session, and historical configuration.
CREATE TABLE system_backup_producer_recovery_revocations (
  scope_key BINARY(32) NOT NULL,
  workload_identity_hash BINARY(32) NOT NULL,
  revocation_epoch BIGINT UNSIGNED NOT NULL,
  revoked_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_key, workload_identity_hash),
  CONSTRAINT ck_prod_recovery_revocation_epoch CHECK (revocation_epoch > 0),
  CONSTRAINT ck_prod_recovery_revocation_version CHECK (row_version > 0)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;
