-- D-owned consumed-nonce ledger. A owns proof parsing, issuer validation and
-- cross-version HMAC lookup; consume this row with the mutation and audit intent.
CREATE TABLE IF NOT EXISTS system_backup_strong_auth_nonces (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-backup-strong-auth-nonce.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  issuer_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  subject_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  session_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  nonce_hmac CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  nonce_hmac_key_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  endpoint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  idempotency_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  authenticated_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6) NOT NULL,
  operation_id BIGINT UNSIGNED NULL,
  response_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  audit_log_id INT NOT NULL,
  retain_until DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_auth_nonce (nonce_hmac, nonce_hmac_key_version),
  KEY idx_sb_auth_nonce_scope (origin_installation_id, endpoint, idempotency_key, id),
  KEY idx_sb_auth_nonce_retention (retain_until, id),
  KEY idx_sb_auth_nonce_key_retention (nonce_hmac_key_version, retain_until, id),
  KEY idx_sb_auth_nonce_operation (operation_id),
  KEY idx_sb_auth_nonce_audit (audit_log_id),
  CONSTRAINT fk_sb_auth_nonce_operation FOREIGN KEY (operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_auth_nonce_audit FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_auth_nonce_identity CHECK (
    schema_version = 'system-backup-strong-auth-nonce.v1'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND issuer_sha256 REGEXP '^[0-9a-f]{64}$'
    AND subject_sha256 REGEXP '^[0-9a-f]{64}$'
    AND session_sha256 REGEXP '^[0-9a-f]{64}$'
    AND nonce_hmac REGEXP '^[0-9a-f]{64}$'
    AND CHAR_LENGTH(nonce_hmac_key_version) BETWEEN 1 AND 128
  ),
  CONSTRAINT chk_sb_auth_nonce_request CHECK (
    endpoint REGEXP '^[A-Za-z][A-Za-z0-9]{0,127}$'
    AND request_hash REGEXP '^[0-9a-f]{64}$'
    AND idempotency_key REGEXP '^[A-Za-z0-9._:-]{16,128}$'
  ),
  CONSTRAINT chk_sb_auth_nonce_result CHECK (
    (operation_id IS NOT NULL AND response_sha256 IS NULL)
    OR (operation_id IS NULL AND response_sha256 IS NOT NULL AND response_sha256 REGEXP '^[0-9a-f]{64}$')
  ),
  CONSTRAINT chk_sb_auth_nonce_times CHECK (
    authenticated_at <= consumed_at AND consumed_at <= expires_at
    AND consumed_at <= created_at AND retain_until > expires_at
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
