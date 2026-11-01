package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/kube"
	d "clawreef/internal/systembackupdispatch"
)

type originalControllerRunKey struct{}
type originalControllerBindingKey struct{}

// The handle is never returned or accepted as an RPC argument. Closing the
// original run cancels and joins operations, including WithoutCancel callers.
type originalControllerRun struct {
	live      atomic.Bool
	mu        sync.RWMutex
	bindings  sync.Mutex
	spentMu   sync.Mutex
	ctx       context.Context
	store     SQLExecutionWorkStore
	authority d.Authority
	spent     map[string]bool
}

func newOriginalControllerRun(s SQLExecutionWorkStore, a d.Authority, ctx context.Context) *originalControllerRun {
	r := &originalControllerRun{ctx: ctx, store: s, authority: a, spent: make(map[string]bool)}
	r.live.Store(true)
	return r
}

func (r *originalControllerRun) close(cancel context.CancelFunc) {
	r.live.Store(false)
	cancel()
	r.mu.Lock()
	r.mu.Unlock()
}

type originalControllerBinding struct {
	run                       *originalControllerRun
	ctx                       context.Context
	record                    kube.ResourceRecord
	key                       string
	readOnly                  bool
	used, prepared, closed    atomic.Bool
	tx                        *sql.Tx
	originalUntil             time.Time
	account, server, database string
}

// WithOriginalControllerBinding scopes the original controller's Bind call.
// Legacy callers without a live-run marker retain their existing Bind behavior
// and gain no renewal path. A marked but invalid/closed scope fails closed.
func WithOriginalControllerBinding(ctx context.Context, a d.Authority, record kube.ResourceRecord, call func(context.Context) (d.JobBinding, error)) (d.JobBinding, error) {
	var zero d.JobBinding
	if ctx == nil || call == nil {
		return zero, ErrExecutionAuthority
	}
	r, _ := ctx.Value(originalControllerRunKey{}).(*originalControllerRun)
	if r == nil {
		return call(ctx)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.live.Load() || r.ctx.Err() != nil || ctx.Err() != nil || a != r.authority || !r.validStore() {
		return zero, ErrExecutionAuthority
	}
	r.bindings.Lock()
	defer r.bindings.Unlock()
	if !r.live.Load() || r.ctx.Err() != nil || ctx.Err() != nil {
		return zero, ErrExecutionAuthority
	}
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	key := record.Intent.Identity.Namespace + "\x00" + record.Intent.Identity.Name + "\x00" + record.UID
	r.spentMu.Lock()
	readOnly := r.spent[key]
	r.spentMu.Unlock()
	f := &originalControllerBinding{run: r, record: record, key: key, readOnly: readOnly}
	f.record.Intent.RequestJSON = bytes.Clone(record.Intent.RequestJSON)
	op = context.WithValue(op, originalControllerBindingKey{}, f)
	f.ctx = op
	defer f.closed.Store(true)
	result, err := call(op)
	if errors.Is(err, ErrExecutionCommitUnknown) {
		r.spentMu.Lock()
		r.spent[key] = true
		r.spentMu.Unlock()
	}
	return result, err
}

func (r *originalControllerRun) validStore() bool {
	s, a := r.store, r.authority
	return s.Queue.Policy.Validate() == nil && s.Queue.DB != nil && s.Queue.DB == s.Authority.DB && s.Queue.Owner == a.ClaimOwner && s.Queue.InstallationID == a.InstallationID && s.Authority.InstallationID == a.InstallationID && s.Queue.ApplicationScope == s.Authority.ApplicationScope && s.Authority.ApplicationScope != "" && s.Authority.DeploymentEnabled && !absentExecutionDependency(s.Authority.Authorization) && sameOriginalExecutionStore(s.Authority, s.Records.Authority) && a.TaskType == "backup" && a.Phase == "capture" && a.MaintenanceFencingToken != 0 && a.MaintenanceOwner == a.TaskPublicID
}

func initialBindingFrame(ctx context.Context, tx *sql.Tx, a d.Authority, guard *ExecutionAuthorityGuard) (*originalControllerBinding, error) {
	if ctx == nil || tx == nil || guard == nil || guard.state == nil {
		return nil, ErrExecutionAuthority
	}
	f, _ := ctx.Value(originalControllerBindingKey{}).(*originalControllerBinding)
	if f == nil {
		return nil, nil
	}
	if f.closed.Load() || f.ctx != ctx || !f.run.live.Load() || f.run.ctx.Err() != nil || ctx.Err() != nil || a != f.run.authority || !f.run.validStore() {
		return nil, ErrExecutionAuthority
	}
	if guard.RecheckOriginal(ctx, tx, f.run.store.Authority, a) != nil {
		return nil, ErrExecutionAuthority
	}
	return f, nil
}

// PrepareOriginalFirstBinding is called only while the original Bind transaction
// holds its complete authority and exact actual-UID Job row. It never commits,
// changes a nonce, or changes a previously bound Job. The old guard is retired;
// the returned NEW guard is only for completing this initial controller binding.
func PrepareOriginalFirstBinding(ctx context.Context, tx *sql.Tx, a d.Authority, guard *ExecutionAuthorityGuard) (*ExecutionAuthorityGuard, error) {
	f, err := initialBindingFrame(ctx, tx, a, guard)
	if err != nil {
		guard.Invalidate()
		return nil, err
	}
	if f == nil {
		return guard, nil
	}
	if f.readOnly || !f.used.CompareAndSwap(false, true) || f.record.Intent.Kind != "Job" || !f.record.CreateDispatched || f.record.UID == "" || f.record.Deleting || f.record.Deleted || f.record.Revision <= 0 || f.record.Intent.Identity.Owner != a.TaskPublicID {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	f.tx = tx
	if checkInitialBindingRow(ctx, tx, a, f, nil) != nil {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&f.account, &f.server, &f.database) != nil {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	f.originalUntil = guard.ValidUntil()
	old := guard.state.first
	oldOwnerUntil := guard.state.until
	if !old.heldCapture || old.status != "capturing" || f.originalUntil.IsZero() {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	f.run.spentMu.Lock()
	f.run.spent[f.key] = true
	f.run.spentMu.Unlock()
	s := f.run.store
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=TIMESTAMPADD(MICROSECOND,?,UTC_TIMESTAMP(6)) WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at=? AND status='capturing' AND UTC_TIMESTAMP(6)<controller_lease_expires_at AND UTC_TIMESTAMP(6)<deadline_at AND UTC_TIMESTAMP(6)<?`, s.Queue.Policy.TTL.Microseconds(), a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion, old.claimUntil, f.originalUntil)
	if err != nil {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	if ok, err := exactlyOneRow(result); err != nil || !ok {
		guard.Invalidate()
		return nil, ErrExecutionAuthority
	}
	guard.Invalidate()
	fresh, err := s.Authority.Bind(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	want, got := old, fresh.state.first
	want.now, want.claimUntil = got.now, got.claimUntil
	if !reflect.DeepEqual(want, got) || !fresh.state.until.Equal(oldOwnerUntil) || got.claimUntil.Before(old.claimUntil) {
		fresh.Invalidate()
		return nil, ErrExecutionAuthority
	}
	f.prepared.Store(true)
	if checkInitialBindingTail(ctx, tx, a, fresh, f, nil) != nil {
		return nil, ErrExecutionAuthority
	}
	return fresh, nil
}

// RecheckOriginalFirstBindingCommit follows the original final owner recheck.
// Existing/recovery/uncoordinated bindings perform no extra effect or renewal.
func RecheckOriginalFirstBindingCommit(ctx context.Context, tx *sql.Tx, a d.Authority, guard *ExecutionAuthorityGuard, binding []byte) error {
	if ctx == nil {
		return ErrExecutionAuthority
	}
	f, _ := ctx.Value(originalControllerBindingKey{}).(*originalControllerBinding)
	if f == nil || !f.prepared.Load() {
		return nil
	}
	return checkInitialBindingTail(ctx, tx, a, guard, f, binding)
}

func checkInitialBindingRow(ctx context.Context, tx *sql.Tx, a d.Authority, f *originalControllerBinding, expected []byte) error {
	r := f.record
	var owner, digest, uid, lifecycle string
	var raw, binding, keyUse, process []byte
	var version int64
	var dispatched, revoked bool
	var stopped sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT resource_owner,request_sha256,request_json,row_version,create_dispatched,COALESCE(observed_uid,''),lifecycle,revoked,stopped_at,binding_json,key_use_json,process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND target_type=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? FOR UPDATE`, a.TaskPublicID, a.TaskType, a.AttemptNo, a.Phase, r.Intent.Identity.Namespace, r.Intent.Identity.Name).Scan(&owner, &digest, &raw, &version, &dispatched, &uid, &lifecycle, &revoked, &stopped, &binding, &keyUse, &process)
	if err != nil || owner != r.Intent.Identity.Owner || digest != r.Intent.RequestSHA256 || !bytes.Equal(raw, r.Intent.RequestJSON) || version != r.Revision || !dispatched || uid != r.UID || lifecycle != "ready" || revoked || stopped.Valid || len(keyUse) != 0 || len(process) != 0 || !bytes.Equal(binding, expected) {
		return ErrExecutionAuthority
	}
	return nil
}

func checkInitialBindingTail(ctx context.Context, tx *sql.Tx, a d.Authority, guard *ExecutionAuthorityGuard, f *originalControllerBinding, expected []byte) error {
	bad := func() error { guard.Invalidate(); return ErrExecutionAuthority }
	if f.closed.Load() || f.ctx != ctx || f.tx != tx || !f.run.live.Load() || f.run.ctx.Err() != nil || ctx.Err() != nil || guard.RecheckOriginal(ctx, tx, f.run.store.Authority, a) != nil {
		return bad()
	}
	// The owner callback has completed. No callback runs after these current Job
	// facts; the held-facts tail and independent delivered clock cover expiry.
	if checkInitialBindingRow(ctx, tx, a, f, expected) != nil {
		return bad()
	}
	state := guard.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.failed || state.ctx != ctx || state.tx != tx || state.authority != a {
		state.failed = true
		return ErrExecutionAuthority
	}
	v, err := state.store.readHeldCapture(ctx, tx, a, state.first, nil)
	var now time.Time
	var account, server, database string
	if err != nil || tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&now, &account, &server, &database) != nil || now.IsZero() || now.Before(v.now) || now.Before(state.floor) || !now.Before(f.originalUntil) || !now.Before(state.first.claimUntil) || !now.Before(state.until) || !now.Before(a.DeadlineAt) || !now.Before(state.first.gateUntil) || !now.Before(state.first.holdUntil) || account != f.account || server != f.server || database != f.database || !f.run.live.Load() || ctx.Err() != nil {
		state.failed = true
		return ErrExecutionAuthority
	}
	state.floor = now
	return nil
}
