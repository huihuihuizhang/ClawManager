-- A -> D proposal, NOT an embedded migration and NOT approved for live apply.
-- Tested only after original 065 DDL in a run-owned isolated probe database.
-- D must assign the migration number, review upgrade behavior and synchronize
-- schema/inventory/catalog/controller before deployment.
ALTER TABLE system_backup_v2_evidence
 DROP CHECK sbv2_chk_sb_evidence_storage,
 DROP CHECK sbv2_chk_sb_evidence_ready_object,
 ADD CONSTRAINT sbv2_chk_sb_evidence_storage CHECK (
  (storage_state='inline' AND storage_provider_role IS NULL AND storage_identity_hash IS NULL
   AND storage_ref_version IS NULL AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL
   AND storage_immutable_version IS NULL AND inline_payload IS NOT NULL
   AND object_checksum IS NULL AND object_size_bytes IS NULL AND plaintext_chunk_size_bytes IS NULL
   AND chunk_count=0 AND chunk_list_root IS NULL)
  OR (storage_state='deleted' AND storage_provider_role IS NULL AND storage_identity_hash IS NULL
   AND storage_ref_version IS NULL AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL
   AND storage_immutable_version IS NULL AND inline_payload IS NULL
   AND object_checksum IS NULL AND object_size_bytes IS NULL AND plaintext_chunk_size_bytes IS NULL
   AND chunk_count=0 AND chunk_list_root IS NULL)
  OR (storage_state NOT IN ('inline','deleted') AND storage_provider_role IS NOT NULL AND storage_provider_role='evidence'
   AND storage_identity_hash IS NOT NULL AND storage_ref_version IS NOT NULL
   AND storage_relative_key IS NOT NULL AND storage_relative_key_hash IS NOT NULL AND inline_payload IS NULL)
 ),
 ADD CONSTRAINT sbv2_chk_sb_evidence_ready_object CHECK (
  NOT (storage_state='ready' OR (storage_state IN ('deleting','delete_failed') AND storage_provider_role='evidence'))
  OR (storage_immutable_version IS NOT NULL AND object_checksum IS NOT NULL AND object_size_bytes IS NOT NULL
   AND plaintext_chunk_size_bytes IS NOT NULL AND plaintext_chunk_size_bytes=1048576 AND chunk_count>=1 AND chunk_list_root IS NOT NULL)
 );
