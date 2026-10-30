-- Synchronous scheduling acknowledgement, never source recovery success.
ALTER TABLE system_backup_v2_operations MODIFY COLUMN operation_type
 ENUM('cancel','cleanup','ownership_resolution','provider_proof_register','finalization_resolution','manual_hold_update','config_update','promotion_create','promotion_revoke','catalog_scan','catalog_import','prune_execute','prune_retry','artifact_health_reconcile','orphan_gc','control_metadata_gc','evidence_gc','evidence_download_admission','capture_reconcile') NOT NULL,
 ADD CONSTRAINT sbv2_chk_capture_reconcile CHECK (operation_type<>'capture_reconcile' OR
 (target_type='backup' AND actor_type='admin' AND endpoint='reconcileSystemBackup' AND status='succeeded' AND http_status=202 AND retryable=FALSE AND failure_category='none' AND result_resource_public_id IS NULL AND result_config_version IS NULL AND started_at IS NOT NULL AND finished_at IS NOT NULL));
