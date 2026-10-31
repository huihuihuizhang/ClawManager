-- 104 omitted one UUID group in the backup reference CHECK. Preserve the
-- original 104 bytes/history; accept exactly the same backup UUID form as 098.
ALTER TABLE system_backup_v2_staging_resources
  DROP CHECK sbv2_chk_sb_staging_identity,
  ADD CONSTRAINT sbv2_chk_sb_staging_identity CHECK (
    schema_version = 'system-backup-staging-resource.v1'
    AND public_id REGEXP '^sbs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND backup_public_id REGEXP '^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND attempt_no >= 1 AND CHAR_LENGTH(phase_uid) BETWEEN 1 AND 128 AND row_version >= 1
  );
