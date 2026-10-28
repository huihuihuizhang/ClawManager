package control

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"clawreef/internal/systembackup/recovery"
)

// CatalogActions is the durable external-action boundary for a six-domain
// driver. The existing functional driver does not silently gain acceptance.
// New tasks need an explicit driver/capability admission path before using it.
type CatalogActions struct {
	Store SQLStore
	Task  Task
	// Admission verifies signed document purpose/identity and provider evidence
	// against the immutable task snapshot. There is no permissive default.
	Admission func(context.Context, *sql.Tx, Task, recovery.Request) error
}

func (j CatalogActions) Prepare(ctx context.Context, r recovery.Request) (recovery.Action, error) {
	if r.Validate() != nil || r.Target.ID == "" || r.Deadline != j.Task.Deadline || j.Admission == nil {
		return recovery.Action{}, ErrInvalid
	}
	raw, e := recovery.Marshal(r)
	if e != nil {
		return recovery.Action{}, ErrInvalid
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return recovery.Action{}, e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return recovery.Action{}, ErrFence
	}
	current, e := load(ctx, tx, j.Task.ID)
	if e != nil || current.Request.Kind != "backup" || current.Status != "publishing" && current.Status != "finalization_unknown" {
		return recovery.Action{}, ErrConflict
	}
	if e = j.Admission(ctx, tx, current, r); e != nil {
		return recovery.Action{}, e
	}
	var stored []byte
	var state string
	e = tx.QueryRowContext(ctx, "SELECT request_json,action_state FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", j.Task.ID, r.ActionID).Scan(&stored, &state)
	if e == nil {
		if !bytes.Equal(raw, stored) {
			return recovery.Action{}, ErrConflict
		}
		return recovery.Action{Request: r, State: state}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) || current.Status != "publishing" {
		return recovery.Action{}, ErrNotReady
	}
	var pending int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_catalog_actions WHERE task_id=? AND action_state IN ('prepared','request_sent','provider_unreachable','conflict','absent')", j.Task.ID).Scan(&pending) != nil || pending != 0 {
		return recovery.Action{}, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_catalog_actions(task_id,action_id,request_json,action_state) VALUES(?,?,?,'prepared')", j.Task.ID, r.ActionID, raw); e != nil || tx.Commit() != nil {
		return recovery.Action{}, ErrNotReady
	}
	return recovery.Action{Request: r, State: "prepared"}, nil
}
func (j CatalogActions) Sent(ctx context.Context, a recovery.Action) error {
	if j.Admission == nil {
		return ErrNotReady
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, j.Task.ID)
	if e != nil || current.Status != "publishing" {
		return ErrFence
	}
	if e = j.Admission(ctx, tx, current, a.Request); e != nil {
		return e
	}
	raw, e := recovery.Marshal(a.Request)
	if e != nil {
		return ErrInvalid
	}
	var stored []byte
	var state string
	if tx.QueryRowContext(ctx, "SELECT request_json,action_state FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", j.Task.ID, a.Request.ActionID).Scan(&stored, &state) != nil || state != "prepared" || !bytes.Equal(stored, raw) {
		return ErrConflict
	}
	var now int64
	if tx.QueryRowContext(ctx, "SELECT "+dbNow).Scan(&now) != nil || now >= a.Request.Deadline {
		return ErrFence
	}
	// A lost transaction response never authorizes sending: the next owner will
	// see request_sent and perform only provider observation.
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_tasks SET can_cancel=FALSE,row_version=row_version+1 WHERE public_id=? AND status='publishing'", j.Task.ID); e != nil {
		return ErrNotReady
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_catalog_actions SET action_state='request_sent' WHERE task_id=? AND action_id=? AND action_state='prepared'", j.Task.ID, a.Request.ActionID)); e != nil {
		return e
	}
	if j.Store.Fence(ctx, tx, j.Task) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (j CatalogActions) Observe(ctx context.Context, a recovery.Action, state string, o recovery.Observation) error {
	switch state {
	case "present", "absent", "conflict", "provider_unreachable":
	default:
		return ErrInvalid
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	raw, _ := recovery.Marshal(a.Request)
	var stored []byte
	var old string
	if tx.QueryRowContext(ctx, "SELECT request_json,action_state FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", j.Task.ID, a.Request.ActionID).Scan(&stored, &old) != nil || !bytes.Equal(stored, raw) {
		return ErrConflict
	}
	if old == state && old != "provider_unreachable" {
		return nil
	}
	if old != "request_sent" && old != "provider_unreachable" {
		return ErrConflict
	}
	var now int64
	if tx.QueryRowContext(ctx, "SELECT "+dbNow).Scan(&now) != nil || o.ValidateOutcome(a.Request, state, now) != nil {
		return ErrNotReady
	}
	observation, e := json.Marshal(o)
	if e != nil {
		return ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_catalog_actions SET action_state=?,observation_json=? WHERE task_id=? AND action_id=?", state, observation, j.Task.ID, a.Request.ActionID); e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
