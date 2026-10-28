package systembackupapi

import (
	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	"encoding/json"
	"errors"
	"github.com/go-sql-driver/mysql"
	uuidlib "github.com/google/uuid"
	"log"
)

// This is a durable stop request, never a stop acknowledgement. It changes no
// capture claim, gate or source state. Only the original execution/recovery
// owner may settle it after proving collector exit and source recovery.
func (s *SQLApplication) stageActiveCancellation(q *taskSQLCapability, kind read.TaskKind, installation, id, actor, endpoint, key, hash, status string) (out read.OperationDTO, resultErr error) {
	stage := "task-state"
	defer func() {
		if resultErr != nil {
			log.Printf("[system-backup-public] cancel-admission=%s", stage)
		}
	}()
	var zero read.OperationDTO
	if kind != read.BackupTask || (status != "preparing" && status != "ready_for_capture" && status != "acquiring_gate" && status != "capturing" && status != "canceling" && status != "validating") {
		return zero, &Error{"conflict_active_job"}
	}
	var original int
	stage = "original-protocol"
	if q.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_execution_inputs i WHERE i.origin_installation_id=? AND i.task_public_id=? AND i.task_type='backup' AND NOT EXISTS(SELECT 1 FROM system_backup_v2_execution_plans p WHERE p.task_public_id=i.task_public_id)`, installation, id).Scan(&original) != nil || original != 1 {
		return zero, &Error{"not_ready"}
	}
	stage = "control-config"
	cfg, err := read.ReadControlConfig(func(query string, args ...any) read.AdmissionRow { return q.QueryRow(query, args...) }, installation, false)
	if err != nil {
		var sqlErr *mysql.MySQLError
		if errors.As(err, &sqlErr) {
			log.Printf("[system-backup-public] cancel-operation-sql=%d", sqlErr.Number)
		}
		return zero, &Error{"not_ready"}
	}
	var values contract.ConfigValues
	stage = "capacity"
	if json.Unmarshal(cfg.Canonical, &values) != nil {
		return zero, &Error{"not_ready"}
	}
	if err = reserveControlCapacity(q, s.cancellationCapacityFile, values.Capacity.ControlMetadataCapacityBytes, 65538); err != nil {
		return zero, err
	}
	operationID := "sop_" + uuidlib.NewString()
	stage = "operation-record"
	_, err = q.Exec(`INSERT INTO system_backup_v2_operations(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,deadline_at,next_reconcile_at) VALUES(?,?,'cancel','backup',?,'admin',?,?,?,?,?,2,?,'pending',TIMESTAMPADD(HOUR,24,UTC_TIMESTAMP(6)),UTC_TIMESTAMP(6))`, operationID, installation, id, actor, endpoint, key, hash, []byte(`[]`), digestJSON([]byte(`[]`)))
	if err != nil {
		var sqlErr *mysql.MySQLError
		if errors.As(err, &sqlErr) {
			log.Printf("[system-backup-public] cancel-operation-sql=%d", sqlErr.Number)
		}
		return zero, &Error{"not_ready"}
	}
	stage = "audit-record"
	_, err = q.Exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) SELECT origin_installation_id,'backup',public_id,'task_status_changed','info',status,'Cancellation requested. Collector exit and source recovery must still be confirmed.',request_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, installation, id)
	if err != nil {
		return zero, &Error{"not_ready"}
	}
	stage = "operation-readback"
	return read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?", installation, operationID), installation)
}
