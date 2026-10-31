-- Capture/secret sends retain their original 120 plan parent. Publication
-- references the SAME task/attempt's authenticated original 122 capture plan;
-- it must never insert a second/placeholder 120 plan merely to satisfy 121.
ALTER TABLE system_backup_v2_job_send_intents
  DROP FOREIGN KEY sbv2_fk_job_send_plan,
  ADD COLUMN legacy_plan_task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin
    GENERATED ALWAYS AS (CASE WHEN phase <> 'publish' THEN task_public_id ELSE NULL END) STORED,
  ADD COLUMN publication_plan_task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin
    GENERATED ALWAYS AS (CASE WHEN phase = 'publish' THEN task_public_id ELSE NULL END) STORED,
  ADD COLUMN publication_plan_phase ENUM('capture') NOT NULL DEFAULT 'capture',
  ADD COLUMN publication_plan_kind ENUM('plan','capture_result') NOT NULL DEFAULT 'plan',
  ADD CONSTRAINT sbv2_chk_job_send_plan_parent CHECK (
    publication_plan_phase='capture' AND publication_plan_kind='plan'),
  ADD CONSTRAINT sbv2_fk_job_send_legacy_plan FOREIGN KEY(origin_installation_id,legacy_plan_task_public_id)
    REFERENCES system_backup_v2_execution_plans(origin_installation_id,task_public_id) ON DELETE RESTRICT,
  ADD CONSTRAINT sbv2_fk_job_send_publication_plan FOREIGN KEY(
    origin_installation_id,publication_plan_task_public_id,attempt_no,publication_plan_phase,publication_plan_kind)
    REFERENCES system_backup_v2_execution_records(
      origin_installation_id,task_public_id,attempt_no,phase,record_kind) ON DELETE RESTRICT;
