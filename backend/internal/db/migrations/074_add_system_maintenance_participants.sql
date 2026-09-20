-- D-owned durable quiesce acknowledgement ledger. Participant pause/resume and
-- watchdog execution belong to the registered writer owners, not this migration.
CREATE TABLE IF NOT EXISTS system_maintenance_participants (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  schema_version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'system-maintenance-participant.v1',
  origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  participant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  gate_generation BIGINT UNSIGNED NOT NULL,
  desired_state ENUM('running', 'paused') NOT NULL DEFAULT 'running',
  observed_state ENUM('running', 'pausing', 'paused', 'resuming', 'error') NOT NULL DEFAULT 'running',
  checkpoint_ref VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
  checkpoint_offset BIGINT UNSIGNED NULL,
  last_completed_mutation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
  heartbeat_at DATETIME(6) NULL,
  pause_requested_at DATETIME(6) NULL,
  pause_ack_at DATETIME(6) NULL,
  resume_requested_at DATETIME(6) NULL,
  resume_ack_at DATETIME(6) NULL,
  resume_result ENUM('none', 'succeeded', 'forced', 'failed') NOT NULL DEFAULT 'none',
  participant_failure_code ENUM('none', 'heartbeat_lost', 'pause_failed', 'resume_failed', 'forced_resume', 'generation_conflict', 'deadline_exceeded', 'internal') NOT NULL DEFAULT 'none',
  failure_at DATETIME(6) NULL,
  row_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uk_sb_participant_scope (origin_installation_id, scope, participant_id),
  KEY idx_sb_participant_gate (origin_installation_id, scope, gate_generation, observed_state, id),
  KEY idx_sb_participant_heartbeat (observed_state, heartbeat_at, id),
  CONSTRAINT fk_sb_participant_gate FOREIGN KEY (origin_installation_id, scope) REFERENCES system_maintenance_locks(origin_installation_id, scope) ON DELETE RESTRICT,
  CONSTRAINT chk_sb_participant_identity CHECK (
    schema_version = 'system-maintenance-participant.v1'
    AND origin_installation_id REGEXP '^installation_[A-Za-z0-9._:-]{1,115}$'
    AND scope REGEXP '^[A-Za-z0-9._:-]{1,128}$'
    AND participant_id REGEXP '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'
    AND gate_generation >= 1 AND row_version >= 1
  ),
  CONSTRAINT chk_sb_participant_checkpoint CHECK (
    (checkpoint_ref IS NULL OR CHAR_LENGTH(checkpoint_ref) BETWEEN 1 AND 256)
    AND (last_completed_mutation_id IS NULL OR CHAR_LENGTH(last_completed_mutation_id) BETWEEN 1 AND 128)
  ),
  CONSTRAINT chk_sb_participant_state CHECK (
    (observed_state = 'running' AND desired_state = 'running' AND (
      (resume_result = 'none' AND participant_failure_code = 'none')
      OR (resume_result = 'succeeded' AND participant_failure_code = 'none')
      OR (resume_result = 'forced' AND participant_failure_code = 'forced_resume')
    ))
    OR (observed_state IN ('pausing', 'paused') AND desired_state = 'paused' AND resume_result = 'none' AND participant_failure_code = 'none')
    OR (observed_state = 'resuming' AND desired_state = 'running' AND resume_result = 'none' AND participant_failure_code = 'none')
    OR (observed_state = 'error' AND participant_failure_code NOT IN ('none', 'forced_resume') AND (
      (resume_result = 'none' AND desired_state = 'paused')
      OR (resume_result = 'failed' AND desired_state = 'running')
    ))
  ),
  CONSTRAINT chk_sb_participant_ack CHECK (
    (observed_state <> 'paused' OR (pause_requested_at IS NOT NULL AND pause_ack_at IS NOT NULL AND heartbeat_at IS NOT NULL))
    AND (pause_ack_at IS NULL OR checkpoint_offset IS NOT NULL OR last_completed_mutation_id IS NOT NULL)
    AND (resume_result NOT IN ('succeeded', 'forced') OR (resume_requested_at IS NOT NULL AND resume_ack_at IS NOT NULL))
    AND (resume_result <> 'failed' OR (observed_state = 'error' AND resume_requested_at IS NOT NULL))
    AND (pause_ack_at IS NULL OR (pause_requested_at IS NOT NULL AND pause_ack_at >= pause_requested_at))
    AND (resume_ack_at IS NULL OR (resume_requested_at IS NOT NULL AND resume_ack_at >= resume_requested_at))
  ),
  CONSTRAINT chk_sb_participant_failure CHECK (
    (participant_failure_code = 'none' AND failure_at IS NULL)
    OR (participant_failure_code <> 'none' AND failure_at IS NOT NULL)
  ),
  CONSTRAINT chk_sb_participant_time CHECK (
    updated_at >= created_at
    AND (heartbeat_at IS NULL OR heartbeat_at >= created_at)
    AND (pause_requested_at IS NULL OR pause_requested_at >= created_at)
    AND (resume_requested_at IS NULL OR resume_requested_at >= created_at)
    AND (failure_at IS NULL OR failure_at >= created_at)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
