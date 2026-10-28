-- D review proposal for migration 081. NOT in the migration runner/catalog.
-- Reconcile number/installed ledger and review exact SQL before promotion.
-- Published migration 066 stays byte-for-byte unchanged. No backfill/seed.
-- NULL old rows preserve read failure until an independently authorized writer
-- verifies their original version-bound bytes against every stored field.
ALTER TABLE system_backup_configs
  ADD COLUMN canonical_config_json MEDIUMBLOB NULL AFTER config_size_bytes,
  ADD CONSTRAINT chk_sb_config_canonical_json CHECK (
    canonical_config_json IS NULL OR (
      OCTET_LENGTH(canonical_config_json) = config_size_bytes
      AND JSON_VALID(CONVERT(canonical_config_json USING utf8mb4))
    )
  );
-- JSON validity/length do not prove UTF-8 JCS, checksum or provenance. Those
-- are mandatory application transaction guards, not claimed by this CHECK.
