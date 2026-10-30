package systembackupapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	uuidlib "github.com/google/uuid"
)

type RecoveryActions struct {
	SchemaVersion  string `json:"schema_version"`
	InstallationID string `json:"origin_installation_id"`
	TaskID         string `json:"public_id"`
	RowVersion     uint64 `json:"row_version"`
	Status         string `json:"status"`
	CanReconcile   bool   `json:"can_reconcile"`
	Reason         string `json:"reason"`
}

func validRecoveryTarget(id string) bool {
	return len(id) == 40 && id[:4] == "sbk_" && uuid.MatchString(id[4:])
}

// Only original capture recovery is supported here. No terminal reset, new
// capture attempt, publication retry or fresh restore is inferred from a status.
func recoveryFacts(q TaskWriteSQL, installation, id string, write bool) (out RecoveryActions, err error) {
	out = RecoveryActions{SchemaVersion: "system-backup-recovery-actions.v1", InstallationID: installation, TaskID: id, Reason: "original_recovery_record_missing"}
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation'"+lock).Scan(&engine) != nil {
		return out, &Error{"not_ready"}
	}
	err = q.QueryRow("SELECT status,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?"+lock, installation, id).Scan(&out.Status, &out.RowVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return out, &Error{"not_found"}
	}
	if err != nil {
		return out, &Error{"not_ready"}
	}
	if engine != "v2" {
		out.Reason = "public_execution_unavailable"
		return out, nil
	}
	switch out.Status {
	case "capturing", "canceling":
	case "canceled":
		out.Reason = "canceled_task_cannot_retry"
		return out, nil
	case "validating", "publishing", "finalization_unknown":
		out.Reason = "publication_continuation_not_connected"
		return out, nil
	default:
		out.Reason = "capture_retry_not_supported"
		return out, nil
	}
	var originals int
	row := q.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_backups b
JOIN system_backup_v2_execution_inputs i ON BINARY i.origin_installation_id=BINARY b.origin_installation_id AND BINARY i.task_public_id=BINARY b.public_id AND i.task_type='backup'
JOIN system_backup_v2_runtime_captures c ON BINARY c.task_public_id=BINARY b.public_id AND c.gate_generation=b.maintenance_fencing_token
WHERE b.origin_installation_id=? AND b.public_id=? AND BINARY b.maintenance_lock_owner=BINARY b.public_id
AND EXISTS(SELECT 1 FROM system_backup_v2_attempts a WHERE a.target_type='backup' AND BINARY a.target_public_id=BINARY b.public_id AND a.phase='capture' AND a.status='running'
 AND EXISTS(SELECT 1 FROM system_backup_v2_execution_records r WHERE BINARY r.origin_installation_id=BINARY b.origin_installation_id AND BINARY r.task_public_id=BINARY b.public_id AND r.attempt_no=a.attempt_no AND BINARY r.phase=BINARY a.phase AND r.record_kind='plan'))
AND NOT EXISTS(SELECT 1 FROM system_backup_v2_execution_plans p WHERE BINARY p.task_public_id=BINARY b.public_id)`, installation, id)
	if sqlrow, ok := row.(taskSQLRow); ok && sqlrow.err != nil {
		var number *mysql.MySQLError
		if errors.As(sqlrow.err, &number) {
			log.Printf("[system-backup-reconcile] original-query-sql=%d", number.Number)
		}
	}
	err = row.Scan(&originals)
	if err != nil {
		return out, &Error{"not_ready"}
	}
	if originals == 1 {
		out.CanReconcile = true
		out.Reason = "original_recovery_only"
	}
	return out, nil
}

func (s *SQLApplication) ReadRecoveryActions(r *http.Request, id string) (RecoveryActions, error) {
	var zero RecoveryActions
	if s == nil || s.reads == nil || s.db == nil {
		return zero, &Error{"not_ready"}
	}
	if !validRecoveryTarget(id) || r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/system-backups/"+id+"/recovery-actions" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return zero, &Error{"validation_failed"}
	}
	scope, err := s.reads.Scope(r)
	if err != nil {
		return zero, applicationError(err)
	}
	ctx, cancel := context.WithTimeout(scope.Context(), s.budget)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, &Error{"not_ready"}
	}
	defer tx.Rollback()
	installation, err := scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return zero, applicationError(err)
	}
	operate, err := scope.CanOperate(ctx, tx)
	if err != nil {
		return zero, applicationError(err)
	}
	q := newTaskSQLCapability(ctx, tx)
	defer q.close()
	out, err := recoveryFacts(q, installation, id, false)
	if err != nil {
		return zero, err
	}
	if !operate {
		out.CanReconcile = false
		out.Reason = "permission_denied"
	}
	if !q.close() {
		return zero, &Error{"not_ready"}
	}
	if err = scope.RecheckRead(ctx, tx, installation); err != nil {
		return zero, applicationError(err)
	}
	if err = tx.Commit(); err != nil {
		return zero, &Error{"not_ready"}
	}
	return out, nil
}

// ReconcileOriginal records an idempotent wake request on the authoritative
// operation ledger. It never expires an owner lease, alters the source gate,
// clears cancellation or manufactures any stop/resume/publication evidence.
func (s *SQLApplication) ReconcileOriginal(r *http.Request, id, key string, body json.RawMessage) (result read.OperationDTO, resultErr error) {
	stage := "input"
	defer func() {
		if resultErr != nil {
			log.Printf("[system-backup-reconcile] admission=%s", stage)
		}
	}()
	var zero read.OperationDTO
	var request struct {
		LookupOnly bool `json:"lookup_only,omitempty"`
	}
	if s == nil || s.db == nil || s.actions == nil {
		return zero, &Error{"not_ready"}
	}
	if r == nil || r.URL == nil || !validRecoveryTarget(id) || r.URL.Path != "/api/v1/admin/system-backups/"+id+"/reconcile" || key != r.Header.Get("Idempotency-Key") || closedJSON(body, &request) != nil {
		return zero, &Error{"validation_failed"}
	}
	stage = "authorization"
	scope, err := s.actions.Scope(r, security.ReconcileSystemBackup)
	if err != nil {
		return zero, applicationError(err)
	}
	ctx, cancel := context.WithTimeout(scope.Context(), s.budget)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, &Error{"not_ready"}
	}
	defer tx.Rollback()
	stage = "session"
	installation, err := scope.AuthorizeAction(ctx, tx)
	if err != nil {
		return zero, applicationError(err)
	}
	actor := strconv.FormatInt(scope.Actor().UserID, 10)
	if scope.Actor().UserID < 1 || key != scope.IdempotencyKey() {
		return zero, &Error{"permission_denied"}
	}
	q := newTaskSQLCapability(ctx, tx)
	defer q.close()
	// Follow the same engine-before-operation/task order as cancellation.
	stage = "engine"
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine) != nil {
		return zero, &Error{"not_ready"}
	}
	hash := digestJSON([]byte(security.ReconcileSystemBackup + ":" + id + ":{}"))
	stage = "idempotency"
	op, err := read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE", installation, actor, security.ReconcileSystemBackup, key), installation)
	if err == nil {
		if op.RequestHash != hash || op.TargetPublicID != id || op.OperationType != "capture_reconcile" {
			return zero, &Error{"idempotency_conflict"}
		}
	} else {
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, &Error{"not_ready"}
		}
		if request.LookupOnly {
			return zero, &Error{"not_found"}
		}
		stage = "original-records"
		facts, e := recoveryFacts(q, installation, id, true)
		if e != nil {
			return zero, e
		}
		if !facts.CanReconcile {
			return zero, &Error{"not_ready"}
		}
		stage = "config"
		cfg, e := read.ReadControlConfig(func(query string, args ...any) read.AdmissionRow { return q.QueryRow(query, args...) }, installation, false)
		if e != nil {
			return zero, &Error{"not_ready"}
		}
		stage = "decode-config"
		var values contract.ConfigValues
		if json.Unmarshal(cfg.Canonical, &values) != nil {
			return zero, &Error{"not_ready"}
		}
		stage = "capacity"
		if e = reserveControlCapacity(q, s.cancellationCapacityFile, values.Capacity.ControlMetadataCapacityBytes, 65538); e != nil {
			return zero, e
		}
		stage = "insert-operation"
		operationID := "sop_" + uuidlib.NewString()
		_, e = q.Exec(`INSERT INTO system_backup_v2_operations(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,http_status,deadline_at,started_at,finished_at) VALUES(?,?,'capture_reconcile','backup',?,'admin',?,?,?,?,?,2,?,'succeeded',202,TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))`, operationID, installation, id, actor, security.ReconcileSystemBackup, key, hash, []byte(`[]`), digestJSON([]byte(`[]`)))
		if e != nil {
			return zero, &Error{"not_ready"}
		}
		// A live owner keeps its exact row version and lease. An unowned/expired
		// original is only made due; the existing controller performs recovery.
		stage = "schedule"
		if _, e = q.Exec("UPDATE system_backup_v2_backups SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE origin_installation_id=? AND public_id=? AND (controller_owner IS NULL OR controller_lease_expires_at<=UTC_TIMESTAMP(6))", installation, id); e != nil {
			return zero, &Error{"not_ready"}
		}
		stage = "audit"
		if _, e = q.Exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) SELECT origin_installation_id,'backup',public_id,'diagnostic.c.reconcile_requested','info',status,'Original-operation reconciliation requested. This acknowledges scheduling only, not recovery or backup success. Active ownership and cancellation are preserved.',request_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, installation, id); e != nil {
			return zero, &Error{"not_ready"}
		}
		stage = "readback"
		op, err = read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?", installation, operationID), installation)
		if err != nil {
			return zero, &Error{"not_ready"}
		}
	}
	if !q.close() || ctx.Err() != nil {
		return zero, &Error{"not_ready"}
	}
	if err = scope.RecheckAction(ctx, tx, installation); err != nil {
		return zero, applicationError(err)
	}
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, &Error{"not_ready"}
	}
	return op, nil
}

type recoveryApplication interface {
	ReadRecoveryActions(*http.Request, string) (RecoveryActions, error)
	ReconcileOriginal(*http.Request, string, string, json.RawMessage) (read.OperationDTO, error)
}

func (h *Handler) RecoveryActions(w http.ResponseWriter, r *http.Request, id, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	if h == nil {
		writeError(w, requestID, nil)
		return
	}
	app, ok := h.application.(recoveryApplication)
	if !ok {
		writeError(w, requestID, nil)
		return
	}
	out, err := app.ReadRecoveryActions(r, id)
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	w.Header().Set("X-System-Backup-Data-Source", "live")
	writeJSON(w, 200, out)
}

func (h *Handler) Reconcile(w http.ResponseWriter, r *http.Request, id, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	if h == nil {
		writeError(w, requestID, nil)
		return
	}
	app, ok := h.application.(recoveryApplication)
	if !ok {
		writeError(w, requestID, nil)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	keys := r.Header.Values("Idempotency-Key")
	if err != nil || media != "application/json" || len(keys) != 1 || !token.MatchString(keys[0]) {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	op, err := app.ReconcileOriginal(r, id, keys[0], body)
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	w.Header().Set("X-System-Backup-Data-Source", "live")
	w.Header().Set("Location", "/api/v1/admin/system-backup-operations/"+op.PublicID)
	writeJSON(w, 202, op)
}
