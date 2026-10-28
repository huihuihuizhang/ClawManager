package systembackupapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	read "clawreef/internal/systembackupread"
)

// The authorized API transaction already owns engine then task locks. This
// operation changes metadata only: it neither touches the physical gate nor
// deletes staging. A later capture may have advanced the shared gate; original
// durable resume/exit receipts, rather than today's gate generation, are proof.
func (s *SQLApplication) cancelReleasedCapture(ctx context.Context, tx *sql.Tx, q *taskSQLCapability, installation, id string) (resultErr error) {
	stage := "unpublished-root"
	defer func() {
		if resultErr != nil {
			log.Printf("[system-backup-public] cancel-released-admission=%s", stage)
		}
	}()
	var epoch, generation uint64
	var owner, registry string
	var frozenRaw []byte
	var stopped, resumed sql.NullTime
	var safe bool
	if err := q.QueryRow(`SELECT maintenance_fencing_token,maintenance_lock_owner,
 artifact_state='staging' AND artifact_usable=FALSE AND controller_owner IS NULL AND controller_lease_expires_at IS NULL
 AND finalization_action_public_id IS NULL AND commit_started_at IS NULL AND artifact_committed_at IS NULL
 AND artifact_uri IS NULL AND manifest_uri IS NULL AND index_uri IS NULL AND marker_uri IS NULL AND acceptance_uri IS NULL
 AND artifact_checksum IS NULL AND manifest_checksum IS NULL AND index_checksum IS NULL AND marker_checksum IS NULL AND acceptance_checksum IS NULL
 AND artifact_registration_id IS NULL AND artifact_registration_hash IS NULL
 FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND status='validating'`, installation, id).Scan(&epoch, &owner, &safe); err != nil || !safe || epoch == 0 || owner != id {
		return &Error{"conflict_active_job"}
	}
	stage = "capture-receipts"
	if err := q.QueryRow(`SELECT gate_generation,registry_sha256,writers_json,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR SHARE`, id).Scan(&generation, &registry, &frozenRaw, &stopped, &resumed); err != nil || generation != epoch || !stopped.Valid || !resumed.Valid || digestJSON(frozenRaw) != registry {
		return &Error{"conflict_active_job"}
	}
	var foreignEffects, jobs, unresolved, sealed int
	stage = "publication-and-collector-effects"
	err := q.QueryRow(`SELECT (SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?) +
 (SELECT COUNT(*) FROM system_backup_v2_artifact_leases WHERE holder_type='backup' AND holder_public_id=?),
 (SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE),
 (SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND (stopped_at IS NULL OR revoked=FALSE)),
 (SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' AND status='sealed')`, id, id, id, id, id).Scan(&foreignEffects, &jobs, &unresolved, &sealed)
	if err != nil || foreignEffects != 0 || jobs == 0 || unresolved != 0 || sealed != 1 {
		log.Printf("[system-backup-public] cancel-released-effects query_failed=%t other=%d jobs=%d unresolved=%d sealed=%d", err != nil, foreignEffects, jobs, unresolved, sealed)
		return &Error{"conflict_active_job"}
	}
	var otherAttempts int
	stage = "original-sealed-attempt"
	if q.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND NOT (phase='capture' AND status='sealed')`, id).Scan(&otherAttempts) != nil || otherAttempts != 0 {
		return &Error{"conflict_active_job"}
	}
	var frozen []b.FrozenWriter
	stage = "frozen-writers"
	if json.Unmarshal(frozenRaw, &frozen) != nil || len(frozen) == 0 {
		return &Error{"not_ready"}
	}
	want := map[string][]byte{}
	for _, writer := range frozen {
		if writer.ID == "" || want[writer.ID] != nil {
			return &Error{"not_ready"}
		}
		want[writer.ID], _ = json.Marshal(d.WriterState{UID: writer.Original.UID, Generation: writer.Original.Generation, Running: writer.Original.Running, Checkpoint: writer.Original.Checkpoint})
	}
	// No capability/transaction escapes the owning authorization transaction.
	rows, err := tx.QueryContext(ctx, `SELECT writer_id,original_json,original_sha256,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=? FOR SHARE`, id)
	if err != nil {
		return &Error{"not_ready"}
	}
	defer rows.Close()
	seen := map[string]bool{}
	stage = "writer-resume-receipts"
	for rows.Next() {
		var writerID, hash string
		var original []byte
		var didResume bool
		if rows.Scan(&writerID, &original, &hash, &didResume) != nil || seen[writerID] || !didResume || digestJSON(original) != hash || want[writerID] == nil || !bytes.Equal(want[writerID], original) {
			return &Error{"conflict_active_job"}
		}
		seen[writerID] = true
	}
	if rows.Err() != nil || len(seen) != len(want) {
		return &Error{"conflict_active_job"}
	}
	if err = rows.Close(); err != nil {
		return &Error{"not_ready"}
	}
	stage = "settle-original-root"
	result, err := q.Exec(`UPDATE system_backup_v2_backups SET status='canceled',can_cancel=FALSE,failure_category='canceled_by_actor',pending_reason='none',attention_reason='none',finished_at=UTC_TIMESTAMP(6),next_reconcile_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND status='validating' AND controller_owner IS NULL`, installation, id)
	if err != nil {
		return &Error{"not_ready"}
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return &Error{"conflict_active_job"}
	}
	return nil
}

func finishReleasedCancellation(q *taskSQLCapability, installation, id, operation string) (read.OperationDTO, error) {
	if _, err := q.Exec(`UPDATE system_backup_v2_operations SET status='succeeded',http_status=202,started_at=UTC_TIMESTAMP(6),finished_at=UTC_TIMESTAMP(6),next_reconcile_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND status='pending'`, installation, operation); err != nil {
		return read.OperationDTO{}, &Error{"not_ready"}
	}
	if _, err := q.Exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) SELECT origin_installation_id,'backup',public_id,'task_status_changed','info','canceled','Canceled before publication after verified collector exit and source recovery. Sealed staging retained.',request_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, installation, id); err != nil {
		return read.OperationDTO{}, &Error{"not_ready"}
	}
	return read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?", installation, operation), installation)
}
