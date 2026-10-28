package systembackupapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	uuidlib "github.com/google/uuid"
)

func cancelRoute(kind read.TaskKind) (path, endpoint, prefix, table string) {
	switch kind {
	case read.BackupTask:
		return "/api/v1/admin/system-backups", security.CancelSystemBackup, "sbk_", "system_backup_v2_backups"
	case read.PreflightTask:
		return "/api/v1/admin/system-backup-preflights", security.CancelSystemBackupPreflight, "spf_", "system_backup_v2_preflights"
	}
	return
}

// CancelUnstarted retains the original API seam. Unstarted work is settled
// directly; public running backups get a durable cancellation request only.
// Their original runner/recovery owner must prove actual exit/source recovery.
func (s *SQLApplication) CancelUnstarted(r *http.Request, kind read.TaskKind, id, key string, body json.RawMessage) (read.OperationDTO, error) {
	var zero read.OperationDTO
	path, endpoint, prefix, table := cancelRoute(kind)
	var empty struct{}
	if s == nil || s.db == nil || s.actions == nil || r == nil || r.URL == nil {
		return zero, &Error{"not_ready"}
	}
	if endpoint == "" || len(id) != 40 || id[:4] != prefix || !uuid.MatchString(id[4:]) || r.URL.Path != path+"/"+id+"/cancel" || key != r.Header.Get("Idempotency-Key") || closedJSON(body, &empty) != nil {
		return zero, &Error{"validation_failed"}
	}
	scope, err := s.actions.Scope(r, endpoint)
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
	// Serialize operation creation with task admission/engine selection. The
	// selected engine is not a cancellation condition: recovery stays available.
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine) != nil {
		return zero, &Error{"not_ready"}
	}
	hash := digestJSON([]byte(endpoint + ":" + id + ":{}"))
	op, err := read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE", installation, actor, endpoint, key), installation)
	if err == nil {
		if op.RequestHash != hash || op.TargetPublicID != id {
			return zero, &Error{"idempotency_conflict"}
		}
	} else {
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, &Error{"not_ready"}
		}
		var status string
		var version uint64
		var owner sql.NullString
		if err = q.QueryRow("SELECT status,row_version,controller_owner FROM "+table+" WHERE origin_installation_id=? AND public_id=? FOR UPDATE", installation, id).Scan(&status, &version, &owner); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return zero, &Error{"not_found"}
			}
			return zero, &Error{"not_ready"}
		}
		if status != "pending" || owner.Valid {
			if kind == read.BackupTask && status == "validating" {
				if err = s.cancelReleasedCapture(ctx, tx, q, installation, id); err != nil {
					return zero, err
				}
			}
			op, err = s.stageActiveCancellation(q, kind, installation, id, actor, endpoint, key, hash, status)
			if err != nil {
				return zero, err
			}
			if status == "validating" {
				op, err = finishReleasedCancellation(q, installation, id, op.PublicID)
				if err != nil {
					return zero, err
				}
			}
		} else {
			var effects uint64
			if q.QueryRow(`SELECT (SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type=? AND target_public_id=?) + (SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type=? AND target_public_id=?) + (SELECT COUNT(*) FROM system_backup_v2_artifact_leases WHERE holder_type=? AND holder_public_id=?)`, string(kind), id, string(kind), id, string(kind), id).Scan(&effects) != nil {
				return zero, &Error{"not_ready"}
			}
			if effects != 0 {
				return zero, &Error{"conflict_active_job"}
			}
			cfg, err := read.ReadControlConfig(func(query string, args ...any) read.AdmissionRow { return q.QueryRow(query, args...) }, installation, false)
			if err != nil {
				return zero, &Error{"not_ready"}
			}
			var values contract.ConfigValues
			if json.Unmarshal(cfg.Canonical, &values) != nil {
				return zero, &Error{"not_ready"}
			}
			if err = reserveControlCapacity(q, s.cancellationCapacityFile, values.Capacity.ControlMetadataCapacityBytes, 65538); err != nil {
				return zero, err
			}
			operationID := "sop_" + uuidlib.NewString()
			// Same row/transaction is authoritative for cancellation and its audit.
			result, err := q.Exec("UPDATE "+table+" SET status='canceled',can_cancel=FALSE,failure_category='canceled_by_actor',pending_reason='none',attention_reason='none',started_at=UTC_TIMESTAMP(6),finished_at=UTC_TIMESTAMP(6),next_reconcile_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND row_version=? AND status='pending' AND controller_owner IS NULL", installation, id, version)
			if err != nil {
				return zero, &Error{"not_ready"}
			}
			n, err := result.RowsAffected()
			if err != nil || n != 1 {
				return zero, &Error{"conflict_active_job"}
			}
			_, err = q.Exec(`INSERT INTO system_backup_v2_operations(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,http_status,deadline_at,started_at,finished_at) VALUES(?,?,'cancel',?,?,'admin',?,?,?,?,?,2,?,'succeeded',202,TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))`, operationID, installation, string(kind), id, actor, endpoint, key, hash, []byte(`[]`), digestJSON([]byte(`[]`)))
			if err != nil {
				return zero, &Error{"not_ready"}
			}
			if _, err = q.Exec("INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) SELECT origin_installation_id,?,public_id,'task_status_changed','info','canceled','Canceled before execution',request_id FROM "+table+" WHERE origin_installation_id=? AND public_id=?", string(kind), installation, id); err != nil {
				return zero, &Error{"not_ready"}
			}
			op, err = read.ScanSubmissionOperation(q.QueryRow("SELECT "+read.SubmissionOperationColumns()+" FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?", installation, operationID), installation)
			if err != nil {
				return zero, &Error{"not_ready"}
			}
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

func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request, kind read.TaskKind, id, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	if h == nil || h.application == nil {
		writeError(w, requestID, &Error{"not_ready"})
		return
	}
	app, ok := h.application.(interface {
		CancelUnstarted(*http.Request, read.TaskKind, string, string, json.RawMessage) (read.OperationDTO, error)
	})
	if !ok {
		writeError(w, requestID, &Error{"not_ready"})
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(keys) != 1 || !token.MatchString(keys[0]) || err != nil || media != "application/json" {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	op, err := app.CancelUnstarted(r, kind, id, keys[0], body)
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/admin/system-backup-operations/"+op.PublicID)
	w.Header().Set("Retry-After", "1")
	w.Header().Set("X-System-Backup-Data-Source", "live")
	writeJSON(w, http.StatusAccepted, op)
}
