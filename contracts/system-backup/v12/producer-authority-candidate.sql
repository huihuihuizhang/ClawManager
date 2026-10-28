-- C1 producer authority DDL candidate. NOT a migration and NOT runtime admission.
-- Requires reviewed A/C inputs (B for Job), MySQL lock/FK/EXPLAIN validation,
-- inventory/catalog synchronization and a separately assigned migration number.
-- Run only in an explicitly selected disposable validation database.
-- Requires MySQL 8.0.16+ or 8.4, InnoDB, strict SQL mode and UTC session.
-- Scope/record correspondence, authenticated lock order, lifecycle transitions,
-- immutable receipts and logical run/evidence FKs remain transaction invariants.
-- No IF NOT EXISTS: an incompatible existing table must not pass silently.

-- DomainRecord; L1; maximum canonical record 16384 bytes.
CREATE TABLE system_backup_producer_domains (
  scope_key BINARY(32) NOT NULL,
  scope_bytes VARBINARY(1024) NOT NULL,
  epoch BIGINT UNSIGNED NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  state ENUM('open', 'closed', 'revoked') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  admission_expires_at DATETIME(6) NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key),
  KEY ix_prod_0_0 (state, admission_expires_at, scope_key),
  CONSTRAINT ck_prod_0_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 16384),
  CONSTRAINT ck_prod_0_1 CHECK (OCTET_LENGTH(scope_bytes) > 0),
  CONSTRAINT ck_prod_0_2 CHECK (epoch > 0),
  CONSTRAINT ck_prod_0_3 CHECK (row_version > 0),
  CONSTRAINT ck_prod_0_4 CHECK (state <> '')
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- GrantRecord; L4; maximum canonical record 32768 bytes.
CREATE TABLE system_backup_producer_grants (
  scope_key BINARY(32) NOT NULL,
  grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  generation BIGINT UNSIGNED NOT NULL,
  domain_epoch BIGINT UNSIGNED NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  state ENUM('active', 'revoked', 'superseded') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  subject_identity_hash BINARY(32) NOT NULL,
  lease_expires_at DATETIME(6) NOT NULL,
  authorization_expires_at DATETIME(6) NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, grant_id),
  UNIQUE KEY uq_prod_1_0 (scope_key, grant_id, generation),
  KEY ix_prod_1_0 (scope_key, state, lease_expires_at, grant_id),
  CONSTRAINT fk_prod_1_0 FOREIGN KEY (scope_key) REFERENCES system_backup_producer_domains (scope_key) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_prod_1_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 32768),
  CONSTRAINT ck_prod_1_1 CHECK (generation > 0),
  CONSTRAINT ck_prod_1_2 CHECK (domain_epoch > 0),
  CONSTRAINT ck_prod_1_3 CHECK (row_version > 0),
  CONSTRAINT ck_prod_1_4 CHECK (state <> ''),
  CONSTRAINT ck_prod_1_5 CHECK (lease_expires_at <= authorization_expires_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- RunRecord; L4; maximum canonical record 16384 bytes.
CREATE TABLE system_backup_producer_runs (
  scope_key BINARY(32) NOT NULL,
  run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_generation BIGINT UNSIGNED NOT NULL,
  target_hash BINARY(32) NOT NULL,
  target_generation BIGINT UNSIGNED NOT NULL,
  evidence_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_write_expires_at DATETIME(6) NOT NULL,
  observed_at DATETIME(6) NULL,
  observation_expires_at DATETIME(6) NULL,
  state ENUM('acquired', 'pending', 'published', 'committed', 'superseded') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, run_id),
  UNIQUE KEY uq_prod_2_0 (evidence_id),
  UNIQUE KEY uq_prod_2_1 (scope_key, grant_id, grant_generation),
  UNIQUE KEY uq_prod_2_2 (scope_key, run_id, evidence_id),
  KEY ix_prod_2_0 (scope_key, target_hash, target_generation),
  KEY ix_prod_2_1 (scope_key, state, owner_write_expires_at, run_id),
  CONSTRAINT fk_prod_2_0 FOREIGN KEY (scope_key, grant_id, grant_generation) REFERENCES system_backup_producer_grants (scope_key, grant_id, generation) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_prod_2_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 16384),
  CONSTRAINT ck_prod_2_1 CHECK (grant_generation > 0),
  CONSTRAINT ck_prod_2_2 CHECK (target_generation > 0),
  CONSTRAINT ck_prod_2_3 CHECK (state <> ''),
  CONSTRAINT ck_prod_2_4 CHECK (row_version > 0),
  CONSTRAINT ck_prod_2_5 CHECK ((observed_at IS NULL AND observation_expires_at IS NULL AND state IN ('acquired', 'superseded')) OR (observed_at IS NOT NULL AND observation_expires_at IS NOT NULL AND observed_at < observation_expires_at))
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- TargetRecord; L5; maximum canonical record 16384 bytes.
CREATE TABLE system_backup_producer_targets (
  scope_key BINARY(32) NOT NULL,
  target_hash BINARY(32) NOT NULL,
  generation BIGINT UNSIGNED NOT NULL,
  current_run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  result_version BIGINT UNSIGNED NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, target_hash),
  CONSTRAINT fk_prod_3_0 FOREIGN KEY (scope_key) REFERENCES system_backup_producer_domains (scope_key) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_prod_3_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 16384),
  CONSTRAINT ck_prod_3_1 CHECK (generation > 0),
  CONSTRAINT ck_prod_3_2 CHECK (row_version > 0)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- HistoricalBindingRecord; L4; maximum canonical record 32768 bytes.
CREATE TABLE system_backup_producer_evidence_bindings (
  scope_key BINARY(32) NOT NULL,
  scope_bytes VARBINARY(1024) NOT NULL,
  run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  grant_generation BIGINT UNSIGNED NOT NULL,
  owner_write_expires_at DATETIME(6) NOT NULL,
  observation_expires_at DATETIME(6) NOT NULL,
  retention_expires_at DATETIME(6) NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, evidence_id),
  UNIQUE KEY uq_prod_4_0 (evidence_id),
  UNIQUE KEY uq_prod_4_1 (scope_key, run_id),
  KEY ix_prod_4_0 (scope_key, owner_write_expires_at, evidence_id),
  CONSTRAINT fk_prod_4_0 FOREIGN KEY (scope_key, run_id, evidence_id) REFERENCES system_backup_producer_runs (scope_key, run_id, evidence_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_prod_4_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 32768),
  CONSTRAINT ck_prod_4_1 CHECK (OCTET_LENGTH(scope_bytes) > 0),
  CONSTRAINT ck_prod_4_2 CHECK (grant_generation > 0),
  CONSTRAINT ck_prod_4_3 CHECK (retention_expires_at >= owner_write_expires_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- ReceiptRecord; L3; maximum canonical record 98304 bytes.
CREATE TABLE system_backup_producer_result_receipts (
  scope_key BINARY(32) NOT NULL,
  scope_bytes VARBINARY(1024) NOT NULL,
  receipt_key_hash BINARY(32) NOT NULL,
  request_hash BINARY(32) NOT NULL,
  run_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_hash BINARY(32) NOT NULL,
  result_version BIGINT UNSIGNED NOT NULL,
  committed_at DATETIME(6) NOT NULL,
  retention_expires_at DATETIME(6) NOT NULL,
  charged_bytes BIGINT UNSIGNED NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, receipt_key_hash),
  UNIQUE KEY uq_prod_5_0 (scope_key, target_hash, result_version),
  KEY ix_prod_5_0 (scope_key, run_id, receipt_key_hash),
  KEY ix_prod_5_1 (scope_key, evidence_id, receipt_key_hash),
  KEY ix_prod_5_2 (scope_key, retention_expires_at, receipt_key_hash),
  CONSTRAINT ck_prod_5_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 98304),
  CONSTRAINT ck_prod_5_1 CHECK (OCTET_LENGTH(scope_bytes) > 0),
  CONSTRAINT ck_prod_5_2 CHECK (result_version > 0),
  CONSTRAINT ck_prod_5_3 CHECK (charged_bytes > 0),
  CONSTRAINT ck_prod_5_4 CHECK (committed_at < retention_expires_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- CommandReceiptRecord; L3; maximum canonical record 65536 bytes.
CREATE TABLE system_backup_producer_command_receipts (
  scope_key BINARY(32) NOT NULL,
  scope_bytes VARBINARY(1024) NOT NULL,
  receipt_key_hash BINARY(32) NOT NULL,
  request_hash BINARY(32) NOT NULL,
  committed_at DATETIME(6) NOT NULL,
  retention_expires_at DATETIME(6) NOT NULL,
  charged_bytes BIGINT UNSIGNED NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, receipt_key_hash),
  KEY ix_prod_6_0 (scope_key, retention_expires_at, receipt_key_hash),
  CONSTRAINT ck_prod_6_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 65536),
  CONSTRAINT ck_prod_6_1 CHECK (OCTET_LENGTH(scope_bytes) > 0),
  CONSTRAINT ck_prod_6_2 CHECK (charged_bytes > 0),
  CONSTRAINT ck_prod_6_3 CHECK (committed_at < retention_expires_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

-- ReferenceRecord; L5; maximum canonical record 8192 bytes.
CREATE TABLE system_backup_producer_evidence_refs (
  scope_key BINARY(32) NOT NULL,
  evidence_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  reference_kind ENUM('producer_result', 'producer_receipt', 'bootstrap_candidate', 'hold') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  reference_key_hash BINARY(32) NOT NULL,
  protected_until DATETIME(6) NOT NULL,
  record_bytes MEDIUMBLOB NOT NULL,
  record_sha256 BINARY(32) NOT NULL,
  PRIMARY KEY (scope_key, evidence_id, reference_kind, reference_key_hash),
  KEY ix_prod_7_0 (scope_key, protected_until, evidence_id),
  CONSTRAINT ck_prod_7_0 CHECK (OCTET_LENGTH(record_bytes) > 0 AND OCTET_LENGTH(record_bytes) <= 8192),
  CONSTRAINT ck_prod_7_1 CHECK (reference_kind <> '')
) ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin;

