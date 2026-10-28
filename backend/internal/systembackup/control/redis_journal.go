package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"clawreef/internal/systembackup/recovery"
)

type RedisJournal struct {
	Store SQLStore
	Task  Task
}
type redisPlan struct {
	Target       recovery.RestoreTarget
	Archive      recovery.Reference
	PolicySHA256 string
	Items        []string
}
type RedisIntent struct {
	Target  recovery.RestoreTarget
	Archive recovery.Reference
	Index   int
	SHA256  string
}
type RedisOutcome struct {
	Intent                          RedisIntent
	Proof                           recovery.Reference
	WriterStopped, Matched, Skipped bool
}
type RedisReconciler interface {
	Observe(context.Context, RedisIntent) (RedisOutcome, error)
}
type RedisProgress struct{ Total, Prepared, Sent, Completed, Skipped int64 }

func (j RedisJournal) transaction(ctx context.Context, reconcile bool) (*sql.Tx, error) {
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return nil, e
	}
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		tx.Rollback()
		return nil, ErrFence
	}
	t, e := load(ctx, tx, j.Task.ID)
	if e != nil || t.Request.Kind != "drill" || t.Request.Purpose != "functional_test" || (!reconcile && t.Status != "restoring") || (reconcile && t.Status != "restoring" && t.Status != "canceling" && t.Status != "normalizing" && t.Status != "verifying") {
		tx.Rollback()
		return nil, ErrFence
	}
	n, e := now(ctx, tx)
	if e != nil || !reconcile && n >= t.Deadline {
		tx.Rollback()
		return nil, ErrFence
	}
	return tx, nil
}
func (j RedisJournal) commit(ctx context.Context, tx *sql.Tx) error {
	if j.Store.Fence(ctx, tx, j.Task) != nil {
		return ErrFence
	}
	if tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (j RedisJournal) Begin(ctx context.Context, target recovery.RestoreTarget, archive recovery.Reference, policy recovery.RedisPolicy, hashes []string) error {
	if hashes == nil {
		hashes = []string{}
	}
	if target.Isolation.Validate() != nil || !identifier.MatchString(target.ID) || !strings.HasPrefix(target.Namespace, "cm-drill-") || !identifier.MatchString(target.Namespace) || !identifier.MatchString(target.Database) || archive.Validate() != nil || policy.Validate() != nil || policy.Purpose != "functional_test" || len(hashes) > 100000 || int64(len(hashes)) > policy.MaxItems {
		return ErrInvalid
	}
	for _, h := range hashes {
		if !revision.MatchString(h) {
			return ErrInvalid
		}
	}
	p, _ := recovery.Marshal(policy)
	raw, e := recovery.Marshal(redisPlan{target, archive, recovery.Hash(p), hashes})
	if e != nil {
		return ErrInvalid
	}
	tx, e := j.transaction(ctx, false)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var stored []byte
	e = tx.QueryRowContext(ctx, "SELECT plan_json FROM system_backup_redis_plans WHERE task_id=? FOR UPDATE", j.Task.ID).Scan(&stored)
	if e == nil {
		if string(raw) != string(stored) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrNotReady
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_redis_plans(task_id,plan_json) VALUES(?,?)", j.Task.ID, raw); e != nil {
		return ErrNotReady
	}
	return j.commit(ctx, tx)
}
func (j RedisJournal) bind(ctx context.Context, tx *sql.Tx, i RedisIntent) error {
	var raw []byte
	var p redisPlan
	if tx.QueryRowContext(ctx, "SELECT plan_json FROM system_backup_redis_plans WHERE task_id=? FOR UPDATE", j.Task.ID).Scan(&raw) != nil || json.Unmarshal(raw, &p) != nil {
		return ErrNotReady
	}
	if p.Target != i.Target || p.Archive != i.Archive || i.Index < 0 || i.Index >= len(p.Items) || p.Items[i.Index] != i.SHA256 {
		return ErrConflict
	}
	return nil
}
func (j RedisJournal) Freeze(ctx context.Context, target recovery.RestoreTarget, archive recovery.Reference, index int, hash string) (string, error) {
	tx, e := j.transaction(ctx, false)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if e = j.bind(ctx, tx, RedisIntent{target, archive, index, hash}); e != nil {
		return "", e
	}
	var state, stored string
	e = tx.QueryRowContext(ctx, "SELECT item_sha256,item_state FROM system_backup_redis_items WHERE task_id=? AND item_no=? FOR UPDATE", j.Task.ID, index).Scan(&stored, &state)
	if e == nil {
		if stored != hash || state != "prepared" && state != "request_sent" && state != "completed" {
			return "", ErrConflict
		}
		return state, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", ErrNotReady
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_redis_items(task_id,item_no,item_sha256,item_state,skipped) VALUES(?,?,?,'prepared',FALSE)", j.Task.ID, index, hash); e != nil {
		return "", ErrNotReady
	}
	if e = j.commit(ctx, tx); e != nil {
		return "", e
	}
	return "prepared", nil
}
func (j RedisJournal) Sent(ctx context.Context, t recovery.RestoreTarget, a recovery.Reference, index int, hash string) error {
	tx, e := j.transaction(ctx, false)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = j.bind(ctx, tx, RedisIntent{t, a, index, hash}); e != nil {
		return e
	}
	var pending int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_redis_items WHERE task_id=? AND item_state='request_sent'", j.Task.ID).Scan(&pending) != nil || pending != 0 {
		return ErrConflict
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_redis_items SET item_state='request_sent' WHERE task_id=? AND item_no=? AND item_sha256=? AND item_state='prepared'", j.Task.ID, index, hash)); e != nil {
		return e
	}
	return j.commit(ctx, tx) // commit uncertainty never grants a send
}
func (j RedisJournal) Done(ctx context.Context, t recovery.RestoreTarget, a recovery.Reference, index int, hash string, skip bool) error {
	return j.done(ctx, RedisIntent{t, a, index, hash}, skip, nil)
}
func (j RedisJournal) done(ctx context.Context, i RedisIntent, skip bool, proof *recovery.Reference) error {
	tx, e := j.transaction(ctx, true)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = j.bind(ctx, tx, i); e != nil {
		return e
	}
	var state, hash string
	var skipped bool
	if tx.QueryRowContext(ctx, "SELECT item_sha256,item_state,skipped FROM system_backup_redis_items WHERE task_id=? AND item_no=? FOR UPDATE", j.Task.ID, i.Index).Scan(&hash, &state, &skipped) != nil || hash != i.SHA256 {
		return ErrConflict
	}
	if state == "completed" {
		if skipped != skip {
			return ErrConflict
		}
		return nil
	}
	if state != "request_sent" {
		return ErrConflict
	}
	b, _ := json.Marshal(proof)
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_redis_items SET item_state='completed',skipped=?,proof_json=? WHERE task_id=? AND item_no=? AND item_state='request_sent'", skip, b, j.Task.ID, i.Index)); e != nil {
		return e
	}
	return j.commit(ctx, tx)
}

// Positive comparison AND proof that the original writer has stopped are
// required. An absent key or lease expiry never authorizes resending.
func (j RedisJournal) Reconcile(ctx context.Context, i RedisIntent, observer RedisReconciler) error {
	if observer == nil {
		return ErrNotReady
	}
	tx, e := j.transaction(ctx, true)
	if e != nil {
		return e
	}
	if e = j.bind(ctx, tx, i); e != nil {
		tx.Rollback()
		return e
	}
	var state, hash string
	e = tx.QueryRowContext(ctx, "SELECT item_sha256,item_state FROM system_backup_redis_items WHERE task_id=? AND item_no=? FOR UPDATE", j.Task.ID, i.Index).Scan(&hash, &state)
	tx.Rollback()
	if e != nil || hash != i.SHA256 {
		return ErrConflict
	}
	if state != "request_sent" {
		return ErrConflict
	}
	out, e := observer.Observe(ctx, i)
	if e != nil || out.Intent != i || out.Proof.Validate() != nil || !out.WriterStopped || !out.Matched {
		return ErrNotReady
	}
	return j.done(ctx, i, out.Skipped, &out.Proof)
}
func (j RedisJournal) Progress(ctx context.Context) (RedisProgress, error) {
	var p RedisProgress
	tx, e := j.transaction(ctx, true)
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	var raw []byte
	var plan redisPlan
	if tx.QueryRowContext(ctx, "SELECT plan_json FROM system_backup_redis_plans WHERE task_id=?", j.Task.ID).Scan(&raw) != nil || json.Unmarshal(raw, &plan) != nil {
		return p, ErrNotReady
	}
	p.Total = int64(len(plan.Items))
	if tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(item_state='prepared'),0),COALESCE(SUM(item_state='request_sent'),0),COALESCE(SUM(item_state='completed'),0),COALESCE(SUM(skipped),0) FROM system_backup_redis_items WHERE task_id=?", j.Task.ID).Scan(&p.Prepared, &p.Sent, &p.Completed, &p.Skipped) != nil {
		return p, ErrNotReady
	}
	return p, nil
}

var _ recovery.RedisRestoreJournal = RedisJournal{}
