package control

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"time"
)

// Schema is installed explicitly by an operator in the independent control DB.
// It is never executed by SQLStore, the API, source collector or worker.
//
//go:embed schema.sql
var Schema string

const dbNow = "CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(3))*1000 AS UNSIGNED)"
const taskColumns = "public_id,actor_id,request_json,status,can_cancel,row_version,generation,controller_owner,controller_lease_until,created_at_ms,deadline_ms,failure_code,profile_revision"

type SQLStore struct{ DB *sql.DB }
type scanner interface{ Scan(...any) error }

func scanTask(row scanner) (Task, error) {
	var t Task
	var request []byte
	e := row.Scan(&t.ID, &t.Actor, &request, &t.Status, &t.CanCancel, &t.RowVersion, &t.Generation, &t.Owner, &t.LeaseUntil, &t.CreatedAt, &t.Deadline, &t.FailureCode, &t.ProfileRevision)
	if errors.Is(e, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if e != nil || json.Unmarshal(request, &t.Request) != nil || t.Request.Validate() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
func (s SQLStore) begin(ctx context.Context) (*sql.Tx, error) {
	if s.DB == nil {
		return nil, ErrNotReady
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return nil, ErrNotReady
	}
	return tx, nil
}
func changed(r sql.Result, e error) error {
	if e != nil {
		return ErrNotReady
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	return nil
}
func now(ctx context.Context, tx *sql.Tx) (int64, error) {
	var n int64
	e := tx.QueryRowContext(ctx, "SELECT "+dbNow).Scan(&n)
	if e != nil {
		return 0, ErrNotReady
	}
	return n, nil
}
func event(ctx context.Context, tx *sql.Tx, t Task, code string) error {
	if !identifier.MatchString(code) {
		return ErrInvalid
	}
	_, e := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(task_id,row_version,code,created_at_ms) VALUES(?,?,?,"+dbNow+")", t.ID, t.RowVersion, code)
	if e != nil {
		return ErrNotReady
	}
	return nil
}
func load(ctx context.Context, tx *sql.Tx, id string) (Task, error) {
	return scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM system_backup_tasks WHERE public_id=? FOR UPDATE", id))
}
func (s SQLStore) Create(ctx context.Context, actor int, key string, r Request, timeout time.Duration) (Task, error) {
	if actor <= 0 || !identifier.MatchString(key) || r.Validate() != nil || timeout < time.Minute || timeout > 24*time.Hour {
		return Task{}, ErrInvalid
	}
	id, e := NewID()
	if e != nil {
		return Task{}, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	existing, e := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM system_backup_tasks WHERE actor_id=? AND idempotency_key=? FOR UPDATE", actor, key))
	if e == nil {
		if existing.Request.Hash() != r.Hash() {
			return Task{}, ErrConflict
		}
		return existing, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return Task{}, e
	}
	// Admission and the capability snapshot serialize in the control DB. An
	// idempotent replay above still returns the original task after expiry.
	var profileBytes []byte
	var ready bool
	if tx.QueryRowContext(ctx, "SELECT profile_json,valid_until_ms>"+dbNow+" FROM system_backup_profiles WHERE profile_id=? FOR UPDATE", r.Profile).Scan(&profileBytes, &ready) != nil || !ready {
		return Task{}, ErrNotReady
	}
	var profile Profile
	if json.Unmarshal(profileBytes, &profile) != nil || !profile.Ready || profile.ID != r.Profile || !revision.MatchString(profile.Revision) {
		return Task{}, ErrNotReady
	}
	supported := false
	for _, kind := range profile.Kinds {
		supported = supported || kind == r.Kind
	}
	if !supported || !profile.Admits(r) {
		return Task{}, ErrNotReady
	}
	timestamp, e := now(ctx, tx)
	if e != nil {
		return Task{}, e
	}
	t := Task{ID: id, Actor: actor, Request: r, ProfileRevision: profile.Revision, Status: "pending", CanCancel: true, RowVersion: 1, CreatedAt: timestamp, Deadline: timestamp + timeout.Milliseconds()}
	body, _ := json.Marshal(r)
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_tasks(public_id,actor_id,idempotency_key,request_sha256,request_json,profile_revision,status,can_cancel,row_version,generation,created_at_ms,deadline_ms) VALUES(?,?,?,?,?,?,'pending',TRUE,1,0,?,?)", id, actor, key, r.Hash(), body, t.ProfileRevision, t.CreatedAt, t.Deadline)
	if e != nil {
		return Task{}, ErrNotReady
	}
	if event(ctx, tx, t, "pending") != nil || tx.Commit() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
func (s SQLStore) Get(ctx context.Context, id string) (Task, error) {
	if s.DB == nil {
		return Task{}, ErrNotReady
	}
	if !identifier.MatchString(id) {
		return Task{}, ErrInvalid
	}
	return scanTask(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM system_backup_tasks WHERE public_id=?", id))
}
func (s SQLStore) List(ctx context.Context, limit int) ([]Task, error) {
	if s.DB == nil {
		return nil, ErrNotReady
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+taskColumns+" FROM system_backup_tasks ORDER BY created_at_ms DESC,public_id DESC LIMIT ?", limit)
	if e != nil {
		return nil, ErrNotReady
	}
	defer rows.Close()
	tasks := []Task{}
	for rows.Next() {
		t, e := scanTask(rows)
		if e != nil {
			return nil, e
		}
		tasks = append(tasks, t)
	}
	if rows.Err() != nil {
		return nil, ErrNotReady
	}
	return tasks, nil
}
func (s SQLStore) Cancel(ctx context.Context, id string, version int64) (Task, error) {
	tx, e := s.begin(ctx)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	t, e := load(ctx, tx, id)
	if e != nil {
		return Task{}, e
	}
	if t.RowVersion != version || !Allowed(t, "canceling") {
		return Task{}, ErrConflict
	}
	e = changed(tx.ExecContext(ctx, "UPDATE system_backup_tasks SET status='canceling',can_cancel=FALSE,row_version=row_version+1 WHERE public_id=? AND row_version=? AND can_cancel=TRUE", id, version))
	if e != nil {
		return Task{}, e
	}
	t.Status = "canceling"
	t.CanCancel = false
	t.RowVersion++
	if event(ctx, tx, t, "canceling") != nil || tx.Commit() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
func (s SQLStore) Claim(ctx context.Context, owner string, ttl time.Duration) (Task, error) {
	return s.claim(ctx, owner, ttl, false)
}

// ClaimFinalization is used only by the read-only publication resolver. Normal
// task execution must never replay an external write in this state.
func (s SQLStore) ClaimFinalization(ctx context.Context, owner string, ttl time.Duration) (Task, error) {
	return s.claim(ctx, owner, ttl, true)
}

func (s SQLStore) claim(ctx context.Context, owner string, ttl time.Duration, finalization bool) (Task, error) {
	if !identifier.MatchString(owner) || ttl < time.Second || ttl > time.Minute {
		return Task{}, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	timestamp, e := now(ctx, tx)
	if e != nil {
		return Task{}, e
	}
	// SKIP LOCKED needs MySQL 8. Finalization-unknown requires exact provider
	// reconciliation, so it is deliberately not replayed by the normal executor.
	filter := "status NOT IN ('succeeded','failed','canceled','finalization_unknown')"
	if finalization {
		filter = "status='finalization_unknown'"
	}
	t, e := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM system_backup_tasks WHERE "+filter+" AND controller_lease_until<=? ORDER BY created_at_ms,public_id LIMIT 1 FOR UPDATE SKIP LOCKED", timestamp))
	if e != nil {
		return Task{}, e
	}
	t.Owner = owner
	t.LeaseUntil = timestamp + ttl.Milliseconds()
	t.Generation++
	t.RowVersion++
	e = changed(tx.ExecContext(ctx, "UPDATE system_backup_tasks SET controller_owner=?,controller_lease_until=?,generation=?,row_version=? WHERE public_id=?", t.Owner, t.LeaseUntil, t.Generation, t.RowVersion, t.ID))
	if e != nil {
		return Task{}, e
	}
	if event(ctx, tx, t, "controller_claimed") != nil || tx.Commit() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
func (s SQLStore) Renew(ctx context.Context, t Task, ttl time.Duration) (Task, error) {
	if s.DB == nil || ttl < time.Second || ttl > time.Minute {
		return Task{}, ErrNotReady
	}
	e := changed(s.DB.ExecContext(ctx, "UPDATE system_backup_tasks SET controller_lease_until="+dbNow+"+? WHERE public_id=? AND controller_owner=? AND generation=? AND controller_lease_until>"+dbNow+" AND status NOT IN ('succeeded','failed','canceled')", ttl.Milliseconds(), t.ID, t.Owner, t.Generation))
	if e != nil {
		return Task{}, ErrFence
	}
	return t, nil
}

// Fence is shared with resource journals. Locks and time checks use this same
// transaction; controller claim is distinct from the maintenance gate.
func (s SQLStore) Fence(ctx context.Context, tx *sql.Tx, t Task) error {
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return ErrFence
	}
	timestamp, e := now(ctx, tx)
	if e != nil || current.Owner != t.Owner || current.Generation != t.Generation || current.LeaseUntil <= timestamp || current.Terminal() {
		return ErrFence
	}
	return nil
}
func (s SQLStore) Advance(ctx context.Context, t Task, next, code string) (Task, error) {
	if code != "" && code != "runner_failed" && code != "deadline_exceeded" && code != "canceled_by_actor" && code != "finalization_unknown" {
		return Task{}, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return Task{}, ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return Task{}, e
	}
	if current.RowVersion != t.RowVersion || !Allowed(current, next) {
		return Task{}, ErrConflict
	}
	terminal := next == "succeeded" || next == "failed" || next == "canceled"
	if terminal {
		// A terminal task must never strand a closed source gate or an unresolved
		// pause. Worker/provider evidence is additionally checked by the executor.
		var pending int
		e = tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE)+(SELECT COUNT(*) FROM system_backup_maintenance WHERE task_id=? AND closed=TRUE)+"+pendingWorkersSQL+"+(SELECT COUNT(*) FROM system_backup_credentials WHERE task_id=? AND removed=FALSE)+(SELECT COUNT(*) FROM system_backup_identities WHERE task_id=? AND deleted=FALSE)+(SELECT COUNT(*) FROM system_backup_redis_items WHERE task_id=? AND item_state='request_sent')+(SELECT COUNT(*) FROM system_backup_recovery_leases WHERE task_id=? AND released=FALSE)+(SELECT COUNT(*) FROM system_backup_v2_prune_runs WHERE task_id=? AND run_state='claimed')+IF(?='succeeded',(SELECT COUNT(*) FROM system_backup_redis_plans p WHERE task_id=? AND COALESCE(JSON_LENGTH(JSON_EXTRACT(plan_json,'$.Items')),-1)<>(SELECT COUNT(*) FROM system_backup_redis_items i WHERE i.task_id=p.task_id AND i.item_state='completed')),0)", t.ID, t.ID, t.ID, t.ID, t.ID, t.ID, t.ID, t.ID, t.ID, next, t.ID).Scan(&pending)
		if e != nil || pending != 0 {
			return Task{}, ErrConflict
		}
		if next == "succeeded" && catalogKind(current.Request.Kind) {
			var count int
			if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_private_records WHERE task_id=? AND record_name='catalog-result' AND record_kind='results'", t.ID).Scan(&count) != nil || count != 1 {
				return Task{}, ErrNotReady
			}
		}
		if next == "succeeded" && current.Request.Kind == "backup" {
			var committed bool
			var commitErr error
			if current.Request.Purpose == "acceptance" {
				var raw []byte
				commitErr = tx.QueryRowContext(ctx, "SELECT result_json FROM system_backup_recovery_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&raw)
				_, commitErr = acceptanceProjection(raw, commitErr)
				committed = commitErr == nil
			} else {
				commitErr = tx.QueryRowContext(ctx, "SELECT committed FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&committed)
			}
			if current.Request.Purpose != "acceptance" && errors.Is(commitErr, sql.ErrNoRows) {
				var count int
				commitErr = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_recovery_publications WHERE task_id=?", t.ID).Scan(&count)
				committed = count == 1
			}
			if commitErr != nil || !committed || current.CanCancel {
				return Task{}, ErrConflict
			}
		}
	}
	cancelable := current.CanCancel && !terminal && next != "canceling" && next != "finalization_unknown"
	e = changed(tx.ExecContext(ctx, "UPDATE system_backup_tasks SET status=?,can_cancel=?,row_version=row_version+1,failure_code=? WHERE public_id=? AND row_version=?", next, cancelable, code, t.ID, t.RowVersion))
	if e != nil {
		return Task{}, e
	}
	t.Status = next
	t.CanCancel = cancelable
	t.RowVersion++
	t.FailureCode = code
	if event(ctx, tx, t, next) != nil || s.FenceBeforeCommit(ctx, tx, t, terminal) != nil || tx.Commit() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
func (s SQLStore) FenceBeforeCommit(ctx context.Context, tx *sql.Tx, t Task, terminal bool) error {
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return ErrFence
	}
	timestamp, e := now(ctx, tx)
	if e != nil || current.Owner != t.Owner || current.Generation != t.Generation || current.LeaseUntil <= timestamp {
		return ErrFence
	}
	return nil
}
func (s SQLStore) BeginCommit(ctx context.Context, t Task) (Task, error) {
	tx, e := s.begin(ctx)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return Task{}, ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil {
		return Task{}, e
	}
	if current.Request.Kind != "backup" || current.Status != "publishing" || current.RowVersion != t.RowVersion {
		return Task{}, ErrConflict
	}
	var started int64
	if tx.QueryRowContext(ctx, "SELECT commit_started_at_ms FROM system_backup_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&started) != nil {
		return Task{}, ErrConflict
	}
	if !current.CanCancel {
		if started <= 0 {
			return Task{}, ErrConflict
		}
		return current, nil
	}
	if started != 0 {
		return Task{}, ErrConflict
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_publications SET commit_started_at_ms="+dbNow+" WHERE task_id=? AND commit_started_at_ms=0", t.ID)); e != nil {
		return Task{}, e
	}
	e = changed(tx.ExecContext(ctx, "UPDATE system_backup_tasks SET can_cancel=FALSE,row_version=row_version+1 WHERE public_id=? AND row_version=? AND can_cancel=TRUE", t.ID, t.RowVersion))
	if e != nil {
		return Task{}, e
	}
	t.CanCancel = false
	t.RowVersion++
	if event(ctx, tx, t, "commit_started") != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return Task{}, ErrNotReady
	}
	return t, nil
}
