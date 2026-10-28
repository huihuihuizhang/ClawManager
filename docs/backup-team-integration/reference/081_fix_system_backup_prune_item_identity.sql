-- 070 omitted the fourth UUID group from artifact_public_id. A valid backup
-- public ID could therefore never satisfy both this CHECK and its backup FK.
-- Keep 070 immutable. Replace the one CHECK atomically for fresh and already
-- migrated installations; all other identity, plan, location and FK checks stay.
ALTER TABLE system_backup_prune_items
  DROP CHECK chk_sb_prune_item_identity,
  ADD CONSTRAINT chk_sb_prune_item_identity CHECK (
    schema_version = 'system-backup-prune-item.v1'
    AND public_id REGEXP '^spi_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND artifact_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );
