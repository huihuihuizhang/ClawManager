package systembackupproducer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeDB struct {
	now                                       time.Time
	server, database                          string
	offset                                    int64
	events                                    []string
	commitError, errorExec                    bool
	affected                                  int64
	workWait, recheckWait, commitWait         time.Duration
	commits, rollbacks                        int
	isolation                                 driver.IsolationLevel
	queryRecord                               func(string, []driver.NamedValue) (driver.Rows, error)
	execRecord                                func(string, []driver.NamedValue) (driver.Result, error)
	beginRecord, commitRecord, rollbackRecord func()
	beforeRollback                            func()
	rollbackDone                              chan struct{}
}
type fakeConnector struct{ s *fakeDB }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{c.s}, nil }
func (c fakeConnector) Driver() driver.Driver                        { return fakeDriver{c.s} }

type fakeDriver struct{ s *fakeDB }

func (d fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{d.s}, nil }

type fakeConn struct{ s *fakeDB }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *fakeConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.s.events = append(c.s.events, "begin")
	c.s.isolation = o.Isolation
	if c.s.beginRecord != nil {
		c.s.beginRecord()
	}
	return &fakeTx{c.s}, nil
}
func (c *fakeConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.s.events = append(c.s.events, q)
	c.s.now = c.s.now.Add(c.s.workWait)
	if c.s.execRecord != nil {
		return c.s.execRecord(q, args)
	}
	if c.s.errorExec {
		return nil, errors.New("synthetic exec failure")
	}
	return driver.RowsAffected(c.s.affected), nil
}
func (c *fakeConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		c.s.events = append(c.s.events, "identity")
		return &fakeRows{values: []driver.Value{c.s.server, c.s.database, c.s.now, c.s.offset}}, nil
	case "SELECT UTC_TIMESTAMP(6)":
		c.s.events = append(c.s.events, "time")
		return &fakeRows{values: []driver.Value{c.s.now}}, nil
	case "SELECT value FROM synthetic FOR UPDATE":
		c.s.events = append(c.s.events, "SELECT value FROM synthetic FOR UPDATE")
		return &fakeRows{values: []driver.Value{int64(1)}}, nil
	case "SELECT value FROM synthetic":
		c.s.events = append(c.s.events, "SELECT value FROM synthetic")
		c.s.now = c.s.now.Add(c.s.recheckWait)
		return &fakeRows{values: []driver.Value{int64(1)}}, nil
	}
	if c.s.queryRecord != nil {
		c.s.events = append(c.s.events, q)
		return c.s.queryRecord(q, args)
	}
	return nil, errors.New("unexpected query")
}

type fakeTx struct{ s *fakeDB }

func (t *fakeTx) Commit() error {
	t.s.events = append(t.s.events, "commit")
	t.s.commits++
	t.s.now = t.s.now.Add(t.s.commitWait)
	if t.s.commitError {
		return errors.New("connection lost during commit")
	}
	if t.s.commitRecord != nil {
		t.s.commitRecord()
	}
	return nil
}
func (t *fakeTx) Rollback() error {
	if t.s.rollbackDone != nil {
		defer close(t.s.rollbackDone)
	}
	if t.s.beforeRollback != nil {
		t.s.beforeRollback()
	}
	t.s.events = append(t.s.events, "rollback")
	t.s.rollbacks++
	if t.s.rollbackRecord != nil {
		t.s.rollbackRecord()
	}
	return nil
}

type fakeRows struct {
	values []driver.Value
	read   bool
}

func (r *fakeRows) Columns() []string { return make([]string, len(r.values)) }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(v []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	copy(v, r.values)
	return nil
}

type fakePolicy struct {
	plan                    GuardPlan
	lockError, recheckError error
	mutateRecheck           bool
}

func (p *fakePolicy) LockAndAuthorize(ctx context.Context, tx SQL, _ Scope) (GuardPlan, error) {
	var n int
	if e := tx.QueryRowContext(ctx, "SELECT value FROM synthetic FOR UPDATE").Scan(&n); e != nil {
		return GuardPlan{}, e
	}
	return p.plan, p.lockError
}
func (p *fakePolicy) Recheck(ctx context.Context, tx ReadSQL, _ Scope, plan GuardPlan, _ time.Time) error {
	var n int
	if e := tx.QueryRowContext(ctx, "SELECT value FROM synthetic").Scan(&n); e != nil {
		return e
	}
	if p.mutateRecheck {
		plan.Deadlines[0] = plan.Deadlines[0].Add(time.Hour)
		if plan.CapacityObservedAt != nil {
			*plan.CapacityObservedAt = plan.CapacityObservedAt.Add(time.Hour)
		}
	}
	return p.recheckError
}
func setupTx(t *testing.T) (*Transactions, *fakeDB, *fakePolicy) {
	t.Helper()
	r, e := DecodeResult(fixtures(t).Positive[0].Value)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 30, 1, 0, 0, 1000, time.UTC)
	s := &fakeDB{now: now, server: string(r.Scope.ServerUUID), database: string(r.Scope.Database), affected: 1}
	db := sql.OpenDB(fakeConnector{s})
	t.Cleanup(func() { db.Close() })
	p := &fakePolicy{plan: GuardPlan{BindingHash: Hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Deadlines: []time.Time{now.Add(10 * time.Second)}}}
	runner, e := NewTransactions(db, r.Scope, p)
	if e != nil {
		t.Fatal(e)
	}
	runner.clock = func() time.Time { return s.now }
	return runner, s, p
}
func TestTransactionOrderAndSealedReceipt(t *testing.T) {
	r, s, _ := setupTx(t)
	var retained *Transaction
	receipt, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
		retained = tx
		return tx.CAS(ctx, "UPDATE synthetic SET value=1")
	})
	if e != nil || !receipt.Committed() {
		t.Fatal(receipt, e)
	}
	want := []string{"begin", "identity", "SELECT value FROM synthetic FOR UPDATE", "time", "UPDATE synthetic SET value=1", "time", "SELECT value FROM synthetic", "time", "commit"}
	if !reflect.DeepEqual(s.events, want) {
		t.Fatal(s.events)
	}
	if s.isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatal("wrong isolation", s.isolation)
	}
	if _, e = retained.ExecContext(context.Background(), "late-write"); !errors.Is(e, ErrGuardRequired) {
		t.Fatal("escaped transaction capability", e)
	}
	if retained.QueryRowContext(context.Background(), "late-read").Scan(new(int)) == nil {
		t.Fatal("escaped query succeeded")
	}
	if _, e = json.Marshal(receipt); !errors.Is(e, ErrInvalid) {
		t.Fatal("receipt became bearer JSON", e)
	}
	if e = json.Unmarshal([]byte(`{"committed":true}`), &CommitReceipt{}); !errors.Is(e, ErrInvalid) {
		t.Fatal("receipt could be forged", e)
	}
	if (CommitReceipt{}).Committed() {
		t.Fatal("zero receipt")
	}
}
func TestGuardedTransactionFailures(t *testing.T) {
	for _, name := range []string{"identity", "timezone", "precision", "missing_deadline", "missing_binding", "lock_denied", "expired_at_start", "work_error", "cas_zero", "cas_many", "exec_error_ignored", "capacity_future", "capacity_stale", "work_wait_expiry", "audit_wait_capacity", "recheck_denied", "recheck_wait_expiry", "recheck_wait_capacity", "mutate_plan_after_lock", "mutate_recheck_plan", "cancel_during_work", "commit_unknown", "commit_expired"} {
		t.Run(name, func(t *testing.T) {
			r, s, p := setupTx(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var rollbackStarted chan struct{}
			var releaseRollback func()
			sample := s.now
			switch name {
			case "cancel_during_work":
				rollbackStarted = make(chan struct{})
				rollbackRelease := make(chan struct{})
				s.rollbackDone = make(chan struct{})
				var releaseOnce sync.Once
				releaseRollback = func() { releaseOnce.Do(func() { close(rollbackRelease) }) }
				defer releaseRollback()
				s.beforeRollback = func() {
					close(rollbackStarted)
					<-rollbackRelease
				}
			case "identity":
				s.server = "wrong"
			case "timezone":
				s.offset = 3600000000
			case "precision":
				s.now = s.now.Add(time.Nanosecond)
			case "missing_deadline":
				p.plan.Deadlines = nil
			case "missing_binding":
				p.plan.BindingHash = ""
			case "lock_denied":
				p.lockError = ErrInvalid
			case "expired_at_start":
				p.plan.Deadlines[0] = s.now
			case "cas_zero":
				s.affected = 0
			case "cas_many":
				s.affected = 2
			case "exec_error_ignored":
				s.errorExec = true
			case "capacity_future":
				sample = sample.Add(time.Microsecond)
				p.plan.CapacityObservedAt = &sample
			case "capacity_stale":
				sample = sample.Add(-5*time.Second - time.Microsecond)
				p.plan.CapacityObservedAt = &sample
			case "work_wait_expiry", "mutate_plan_after_lock":
				s.workWait = 10 * time.Second
			case "audit_wait_capacity":
				p.plan.CapacityObservedAt = &sample
				s.workWait = 6 * time.Second
			case "recheck_denied":
				p.recheckError = ErrInvalid
			case "recheck_wait_expiry", "mutate_recheck_plan":
				s.recheckWait = 10 * time.Second
				p.mutateRecheck = name == "mutate_recheck_plan"
			case "recheck_wait_capacity":
				p.plan.CapacityObservedAt = &sample
				s.recheckWait = 6 * time.Second
			case "commit_unknown":
				s.commitError = true
			case "commit_expired":
				s.commitWait = 10 * time.Second
			}
			receipt, e := r.Run(ctx, func(ctx context.Context, tx *Transaction) error {
				if name == "work_error" {
					return ErrInvalid
				}
				if name == "cancel_during_work" {
					cancel()
					// Force database/sql's cancellation goroutine to own rollback.
					// Run's deferred Rollback can then return ErrTxDone while the
					// driver is still blocked, reproducing the observed race.
					select {
					case <-rollbackStarted:
					case <-time.After(5 * time.Second):
						releaseRollback()
						t.Error("cancellation did not start driver rollback")
					}
					return nil
				}
				if name == "mutate_plan_after_lock" {
					p.plan.Deadlines[0] = s.now.Add(time.Hour)
				}
				_ = tx.CAS(ctx, "UPDATE synthetic SET value=1") // deliberately ignored: executor must latch it
				return nil
			})
			if releaseRollback != nil {
				releaseRollback()
				// Synchronize before reading counters/events written by the
				// asynchronous driver. Do not weaken the exactly-one assertion.
				select {
				case <-s.rollbackDone:
				case <-time.After(5 * time.Second):
					t.Fatal("driver rollback did not finish")
				}
			}
			if e == nil {
				t.Fatal("unsafe success", s.events)
			}
			if name == "commit_unknown" {
				if !errors.Is(e, ErrCommitUnknown) || receipt.Committed() || s.commits != 1 {
					t.Fatal(e, receipt, s.events)
				}
			} else if name == "commit_expired" {
				if !errors.Is(e, ErrCommittedExpired) || !receipt.Committed() || s.commits != 1 {
					t.Fatal(e, receipt, s.events)
				}
			} else if s.commits != 0 || receipt.Committed() || s.rollbacks != 1 {
				t.Fatal("failure did not roll back", e, receipt, s.events)
			}
		})
	}
}
func TestMissingGuardNeverStartsWork(t *testing.T) {
	r, _, _ := setupTx(t)
	var absent *fakePolicy
	if _, e := NewTransactions(r.db, r.scope, absent); !errors.Is(e, ErrGuardRequired) {
		t.Fatal(e)
	}
	if _, e := NewTransactions(r.db, r.scope, nil); !errors.Is(e, ErrGuardRequired) {
		t.Fatal(e)
	}
	if _, e := r.Run(context.Background(), nil); !errors.Is(e, ErrGuardRequired) {
		t.Fatal(e)
	}
	var missing *Transactions
	if _, e := missing.Run(context.Background(), func(context.Context, *Transaction) error { t.Fatal("called"); return nil }); e == nil {
		t.Fatal("nil executor")
	}
}
func TestCapacityFiveSecondBoundary(t *testing.T) {
	r, s, p := setupTx(t)
	sample := s.now.Add(-5 * time.Second)
	p.plan.CapacityObservedAt = &sample
	if _, e := r.Run(context.Background(), func(context.Context, *Transaction) error { return nil }); e != nil {
		t.Fatal("exactly 5 seconds allowed", e)
	}
}

func TestWorkCannotCommitBeforeGuard(t *testing.T) {
	for _, query := range []string{"COMMIT", "ROLLBACK", "SET autocommit=1", "CREATE TABLE x(id INT)", "UPDATE synthetic SET value=1; COMMIT", "/* bypass */ COMMIT", "CALL commit_work()"} {
		t.Run(query, func(t *testing.T) {
			r, s, _ := setupTx(t)
			_, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error { _, _ = tx.ExecContext(ctx, query); return nil })
			if !errors.Is(e, ErrGuardRequired) || s.commits != 0 || s.rollbacks != 1 {
				t.Fatal("control SQL escaped guard", e, s.events)
			}
		})
	}
}
