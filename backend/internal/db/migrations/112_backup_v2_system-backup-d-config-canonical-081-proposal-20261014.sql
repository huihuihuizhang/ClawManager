-- Integration-reviewed isolated control schema. No production activation or grants.

SET @sb_v2_ddl = IF((SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' AND COLUMN_NAME='canonical_config_json')=0, 'ALTER TABLE system_backup_v2_configs
  ADD COLUMN canonical_config_json MEDIUMBLOB NULL AFTER config_size_bytes,
  ADD CONSTRAINT sbv2_chk_sb_config_canonical_json CHECK (
    canonical_config_json IS NULL OR (
      OCTET_LENGTH(canonical_config_json) = config_size_bytes
      AND JSON_VALID(CONVERT(canonical_config_json USING utf8mb4))
    )
  )', 'SELECT 1');
PREPARE sb_v2_stmt FROM @sb_v2_ddl;
EXECUTE sb_v2_stmt;
DEALLOCATE PREPARE sb_v2_stmt;
