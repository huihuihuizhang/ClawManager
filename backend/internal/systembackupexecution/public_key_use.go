package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
)

// Called only after original task/plan/mTLS/TokenReview/current process checks
// and SQLExecutionAuthority.Bind, while the SAME original Job row is locked.
// Revoke serializes on that row. A completed revoke still requires Stopped;
// this record must never be treated as proof that a process was terminated.
func (o *PublicJobOwner) keyUseTx(ctx context.Context, tx *sql.Tx, a d.Authority, binding d.JobBinding, pod BoundPod, req worker.ControlRequest, until time.Time) (*worker.KeyUseLease, error) {
	// All owner/permit/capability/relay minima are fixed BEFORE the original
	// lease is persisted or signed. DATETIME(6) cannot retain nanoseconds; floor
	// in UTC once here, never round up or repair a signed lease on readback.
	until = until.UTC().Truncate(time.Microsecond)
	var old []byte
	if tx.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND lifecycle='ready' AND stopped_at IS NULL FOR UPDATE`, a.TaskPublicID, a.AttemptNo, binding.Namespace, binding.Name, binding.UID).Scan(&old) != nil {
		return nil, c.ErrExecutionAuthority
	}
	rawAuthority, e := json.Marshal(a)
	if e != nil {
		return nil, c.ErrExecutionAuthority
	}
	current := worker.KeyUseLease{Identity: k.JobIdentity{Namespace: pod.Namespace, PodUID: pod.UID, ServiceAccountUID: pod.ServiceAccountUID, JobUID: binding.UID, InvocationSHA256: req.InvocationSHA256, ExecutionGrantSHA256: o.Identity.GrantSHA256()}, Access: *req.Invocation.ProviderKey, AuthoritySHA256: hash(rawAuthority), Nonce: req.Point, Until: until}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return nil, c.ErrExecutionAuthority
	}
	advance := advanceKeyUse
	if req.Invocation.FormalCapture != nil && req.Invocation.FormalCapture.PermitDelivery != nil {
		advance = advanceDeliveredKeyUse
	}
	next, changed, e := advance(old, current, req.Action, now)
	if e != nil {
		return nil, e
	}
	if changed {
		encoded, e := json.Marshal(next)
		if e != nil || len(encoded) > 16384 {
			return nil, c.ErrExecutionRecord
		}
		result, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_resources SET key_use_json=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND stopped_at IS NULL`, encoded, a.TaskPublicID, a.AttemptNo, binding.Namespace, binding.Name, binding.UID)
		if e != nil {
			return nil, e
		}
		if count, e := result.RowsAffected(); e != nil || count != 1 {
			return nil, c.ErrExecutionRecord
		}
	}
	return &next, nil
}

func advanceDeliveredKeyUse(raw []byte, current worker.KeyUseLease, action string, now time.Time) (worker.KeyUseLease, bool, error) {
	if action == "key-reserve" && len(raw) != 0 {
		original, _, err := advanceKeyUse(raw, current, "key-check", now)
		if err != nil || original.State != "reserved" {
			return worker.KeyUseLease{}, false, c.ErrExecutionAuthority
		}
		return original, false, nil
	}
	return advanceKeyUse(raw, current, action, now)
}

func advanceKeyUse(raw []byte, current worker.KeyUseLease, action string, now time.Time) (worker.KeyUseLease, bool, error) {
	deny := func() (worker.KeyUseLease, bool, error) { return worker.KeyUseLease{}, false, c.ErrExecutionAuthority }
	if now.IsZero() || !now.Before(current.Until) {
		return deny()
	}
	if len(raw) == 0 {
		if action != "key-reserve" {
			return deny()
		}
		current.State = "reserved"
		return current, true, nil
	}
	if len(raw) > 16384 || action == "key-reserve" {
		return deny()
	}
	var original worker.KeyUseLease
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&original) != nil || dec.Decode(new(any)) != io.EOF || !now.Before(original.Until) || current.Until.Before(original.Until) {
		return deny()
	}
	// Refuse a renewed claim, changed Job/Pod/grant/key/context or nonce. The
	// original shorter window is retained even when current bounds are longer.
	want, got := original, current
	want.State, got.State = "", ""
	got.Until = want.Until
	if want != got {
		return deny()
	}
	switch action {
	case "candidate":
		if original.State != "finished" {
			return deny()
		}
		return original, false, nil
	case "key-check":
		if original.State != "reserved" && original.State != "using" && original.State != "finished" {
			return deny()
		}
		return original, false, nil
	case "key-begin":
		if original.State != "reserved" {
			return deny()
		}
		original.State = "using"
	case "key-end":
		if original.State != "using" {
			return deny()
		}
		original.State = "finished"
	default:
		return deny()
	}
	return original, true, nil
}
