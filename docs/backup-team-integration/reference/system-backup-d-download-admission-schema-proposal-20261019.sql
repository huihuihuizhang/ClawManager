-- D candidate only: NOT a numbered migration, approval or production activation.
-- Reviewed numbered append must follow the actual target ledger, not assume 083.
-- No UPDATE/backfill of existing evidence installation ownership is authorized.
-- Existing NULL rows stay inaccessible to this new admission path until their
-- owner/install relationship is independently established by a reviewed writer.
-- MySQL DDL has implicit commits: deploy only as an inspected migration, never
-- inside a download admission transaction. No grants or triggers are installed.

ALTER TABLE system_backup_evidence
  ADD COLUMN origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  ADD UNIQUE KEY uk_sb_evidence_installation_id_public (origin_installation_id,id,public_id),
  ADD CONSTRAINT fk_sb_evidence_installation FOREIGN KEY (origin_installation_id)
    REFERENCES system_backup_installation_state(origin_installation_id) ON DELETE RESTRICT;

ALTER TABLE system_backup_operations
  MODIFY COLUMN operation_type ENUM('cancel', 'cleanup', 'ownership_resolution', 'provider_proof_register', 'finalization_resolution', 'manual_hold_update', 'config_update', 'promotion_create', 'promotion_revoke', 'catalog_scan', 'catalog_import', 'prune_execute', 'prune_retry', 'artifact_health_reconcile', 'orphan_gc', 'control_metadata_gc', 'evidence_gc', 'evidence_download_admission') NOT NULL,
  MODIFY COLUMN target_type ENUM('backup', 'backup_staging', 'external_action', 'drill', 'restore_resource', 'preflight', 'artifact_verify', 'catalog_scan', 'catalog_import', 'prune_run', 'promotion', 'matrix', 'system', 'evidence') NOT NULL,
  ADD COLUMN download_evidence_id BIGINT UNSIGNED NULL,
  ADD UNIQUE KEY uk_sb_operation_installation_id (origin_installation_id,id),
  ADD UNIQUE KEY uk_sb_operation_download_binding (origin_installation_id,id,public_id,download_evidence_id),
  ADD CONSTRAINT fk_sb_operation_download_evidence
    FOREIGN KEY (origin_installation_id,download_evidence_id,target_public_id)
    REFERENCES system_backup_evidence(origin_installation_id,id,public_id) ON DELETE RESTRICT,
  DROP CHECK chk_sb_operation_target_id,
  ADD CONSTRAINT chk_sb_operation_target_id CHECK (
    (target_type = 'backup' AND target_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'backup_staging' AND target_public_id REGEXP '^sbs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'external_action' AND target_public_id REGEXP '^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'drill' AND target_public_id REGEXP '^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'restore_resource' AND target_public_id REGEXP '^srr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'preflight' AND target_public_id REGEXP '^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'artifact_verify' AND target_public_id REGEXP '^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_scan' AND target_public_id REGEXP '^scs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'catalog_import' AND target_public_id REGEXP '^sci_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'prune_run' AND target_public_id REGEXP '^spr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'promotion' AND target_public_id REGEXP '^spm_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (target_type = 'matrix' AND target_public_id IN ('k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node'))
    OR (target_type = 'system' AND target_public_id = origin_installation_id AND target_public_id REGEXP '^installation_')
    OR (target_type = 'evidence' AND target_public_id REGEXP '^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  ADD CONSTRAINT chk_sb_operation_download_admission CHECK (
    (operation_type <> 'evidence_download_admission' AND download_evidence_id IS NULL AND target_type <> 'evidence')
    OR (operation_type = 'evidence_download_admission'
      AND download_evidence_id IS NOT NULL AND target_type = 'evidence'
      AND actor_type = 'admin' AND endpoint = 'getSystemBackupEvidence'
      AND status = 'succeeded' AND retryable = FALSE AND failure_category = 'none'
      AND failure_message IS NULL AND http_status IS NOT NULL AND http_status = 200
      AND result_resource_public_id IS NULL AND result_config_version IS NULL
      AND retry_of_operation_public_id IS NULL AND row_version = 1
      AND redacted_response_evidence_id IS NULL AND redacted_response_sha256 IS NULL
      AND external_action_public_ids_canonical_json = _binary'[]'
      AND external_action_public_ids_size_bytes = 2
      AND external_action_public_ids_sha256 = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
      AND claim_owner IS NULL AND claim_expires_at IS NULL AND next_reconcile_at IS NULL
      AND started_at IS NOT NULL AND finished_at IS NOT NULL
      AND started_at = created_at AND finished_at = created_at AND updated_at = created_at)
  );

-- Strengthen the existing nonce operation FK for EVERY non-NULL operation link.
-- Reject legacy cross-installation links; never silently repair them.
ALTER TABLE system_backup_strong_auth_nonces
  ADD CONSTRAINT fk_sb_auth_nonce_operation_installation
    FOREIGN KEY (origin_installation_id,operation_id)
    REFERENCES system_backup_operations(origin_installation_id,id) ON DELETE RESTRICT;

-- One immutable row contains independently hashed private receipt and public
-- Operation bytes. Public readers must SELECT ONLY the public projection after
-- current A authorization; never serialize this table or SELECT * into a DTO.
-- No raw nonce/proof/claim/session/bearer/provider locator is stored here.
CREATE TABLE system_backup_download_admission_receipts (
  operation_id BIGINT UNSIGNED NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  operation_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_id BIGINT UNSIGNED NOT NULL,
  evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  intent_audit_id INT NOT NULL,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
    DEFAULT 'system-backup-evidence-download-admission.v1',
  receipt_canonical_json BLOB NOT NULL,
  receipt_size_bytes INT UNSIGNED NOT NULL,
  receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  operation_canonical_json BLOB NOT NULL,
  operation_size_bytes INT UNSIGNED NOT NULL,
  operation_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  admitted_at DATETIME(6) NOT NULL,
  claim_expires_at DATETIME(6) NOT NULL,
  deadline_at DATETIME(6) NOT NULL,
  retain_until DATETIME(6) NOT NULL,
  PRIMARY KEY (operation_id),
  UNIQUE KEY uk_sb_download_receipt_public (origin_installation_id,operation_public_id),
  UNIQUE KEY uk_sb_download_receipt_result_group (origin_installation_id,operation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,retain_until),
  KEY idx_sb_download_receipt_evidence (origin_installation_id,evidence_id,evidence_public_id),
  KEY idx_sb_download_receipt_retention (retain_until,operation_id),
  CONSTRAINT fk_sb_download_receipt_operation
    FOREIGN KEY (origin_installation_id,operation_id,operation_public_id,evidence_id)
    REFERENCES system_backup_operations(origin_installation_id,id,public_id,download_evidence_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_download_receipt_evidence
    FOREIGN KEY (origin_installation_id,evidence_id,evidence_public_id)
    REFERENCES system_backup_evidence(origin_installation_id,id,public_id) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_download_receipt_audit FOREIGN KEY (intent_audit_id)
    REFERENCES audit_logs(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_download_receipt_schema CHECK (schema_version='system-backup-evidence-download-admission.v1'),
  CONSTRAINT chk_sb_download_receipt_bytes CHECK (
    receipt_size_bytes BETWEEN 2 AND 8192 AND operation_size_bytes BETWEEN 2 AND 8192
    AND receipt_size_bytes=OCTET_LENGTH(receipt_canonical_json)
    AND operation_size_bytes=OCTET_LENGTH(operation_canonical_json)
    AND receipt_sha256 REGEXP '^[0-9a-f]{64}$' AND operation_sha256 REGEXP '^[0-9a-f]{64}$'
    AND JSON_VALID(CONVERT(receipt_canonical_json USING utf8mb4))
    AND JSON_VALID(CONVERT(operation_canonical_json USING utf8mb4))
    AND JSON_TYPE(CONVERT(receipt_canonical_json USING utf8mb4))='OBJECT'
    AND JSON_TYPE(CONVERT(operation_canonical_json USING utf8mb4))='OBJECT'
  ),
  CONSTRAINT chk_sb_download_receipt_times CHECK (
    admitted_at < deadline_at AND deadline_at <= claim_expires_at
    AND retain_until > claim_expires_at
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One separately immutable result link; the admission receipt remains unchanged.
-- Insert in the independent result transaction, after the actual audit INSERT
-- and before the exact claim-release CAS. Lock its absent operation key at L3.
-- Both evidence columns participate in the closed L3 reference prefix.
CREATE TABLE system_backup_download_result_receipts (
  operation_id BIGINT UNSIGNED NOT NULL,
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  operation_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_id BIGINT UNSIGNED NOT NULL,
  evidence_public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  intent_audit_id INT NOT NULL,
  result_audit_id INT NOT NULL,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
    DEFAULT 'system-backup-evidence-download-result.v1',
  result_size_bytes INT UNSIGNED NOT NULL,
  result_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  result_at DATETIME(6) NOT NULL,
  retain_until DATETIME(6) NOT NULL,
  PRIMARY KEY (operation_id),
  UNIQUE KEY uk_sb_download_result_audit (result_audit_id),
  KEY idx_sb_download_result_evidence (origin_installation_id,evidence_id,evidence_public_id),
  KEY idx_sb_download_result_retention (retain_until,operation_id),
  CONSTRAINT fk_sb_download_result_group
    FOREIGN KEY (origin_installation_id,operation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,retain_until)
    REFERENCES system_backup_download_admission_receipts(origin_installation_id,operation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,retain_until) ON DELETE RESTRICT,
  CONSTRAINT fk_sb_download_result_audit FOREIGN KEY (result_audit_id)
    REFERENCES audit_logs(id) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_download_result_schema CHECK (schema_version='system-backup-evidence-download-result.v1'),
  CONSTRAINT chk_sb_download_result_body CHECK (
    result_size_bytes BETWEEN 2 AND 2048 AND result_sha256 REGEXP '^[0-9a-f]{64}$'
    AND result_audit_id <> intent_audit_id
  ),
  CONSTRAINT chk_sb_download_result_times CHECK (result_at < retain_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admission account: receipt INSERT/SELECT only, no UPDATE/DELETE; existing
-- audit anchors must likewise be protected from UPDATE/DELETE. Review the
-- effective privileges inherited from roles and database-wide grants.
-- GC uses a separate reviewed identity, checks all hold/ref/retention guards,
-- then removes nonce -> receipt -> operation/audit as one retention group.
-- FK RESTRICT alone does not make an audit or receipt immutable.
-- The result identity has result-receipt INSERT/SELECT only; no UPDATE/DELETE
-- on either receipt, original Operation/nonce/intent or result audit. Capacity
-- measurement includes the additional result row, all indexes and FK work.
-- Group GC must acquire the same L0..L5 prefix, all current holds/refs, original
-- retain_until and later retention extensions, then remove result link/audit,
-- nonce, admission receipt, Operation/intent in one reviewed transaction. There
-- is no general-purpose result-receipt DELETE permission or automatic cascade.
-- retain_until freezes the MAX of admission+control-retention, target's current
-- protected_until and every nonce/idempotency/audit minimum. Later config must
-- not shorten it. Actual physical page/index/audit reservation is mandatory.
-- No generic writer/GC may clear evidence origin_installation_id after binding.

