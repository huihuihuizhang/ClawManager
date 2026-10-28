package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"
)

type recoveryScanDB struct {
	*recoveryDB
	c                       WriteRecoveryConfig
	rows                    [][]driver.Value
	after                   int64
	limit                   int
	scanning, scanCommitted bool
	queryErr, rowsErr       bool
	afterScan               func()
}

func (d *recoveryScanDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *recoveryScanDB) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	d.scanning = false
	if _, err := d.recoveryDB.BeginTx(ctx, opts); err != nil {
		return nil, err
	}
	return d, nil
}
func (d *recoveryScanDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q != recoveryCandidatesSQL {
		return d.recoveryDB.QueryContext(ctx, q, args)
	}
	if d.index != 4 {
		d.t.Fatal("scan before config admission")
	}
	prefix := d.c.Root + "/" + d.c.Registry.Installation + "/"
	want := []any{d.after, d.c.Store.Identity, d.c.Store.Version, int64(len(prefix)), prefix, int64(d.limit + 1)}
	if len(args) != len(want) {
		d.t.Fatal("unbounded scan args")
	}
	for i, arg := range args {
		if !reflect.DeepEqual(arg.Value, want[i]) {
			d.t.Fatalf("wrong scan argument %d", i)
		}
	}
	d.scanning = true
	d.index = 7 // scan has no per-owner locks/manifest; these occur on dispatch
	if d.queryErr {
		return nil, errors.New("PRIVATE_SQL_ERROR")
	}
	return &recoveryScanRows{rows: d.rows, fail: d.rowsErr}, nil
}
func (d *recoveryScanDB) Commit() error {
	if !d.scanning {
		return d.recoveryDB.Commit()
	}
	plan := d.plan
	d.plan = plan[:8] // final database clock after the bounded scan
	err := d.recoveryDB.Commit()
	d.plan = plan
	if err == nil {
		d.scanCommitted = true
		if d.afterScan != nil {
			d.afterScan()
		}
	}
	return err
}

type recoveryScanRows struct {
	rows  [][]driver.Value
	index int
	fail  bool
}

func (r *recoveryScanRows) Columns() []string { return []string{"id", "public_id"} }
func (r *recoveryScanRows) Close() error      { return nil }
func (r *recoveryScanRows) Next(dst []driver.Value) error {
	if r.index == len(r.rows) {
		if r.fail {
			return errors.New("PRIVATE_ROW_ERROR")
		}
		return io.EOF
	}
	copy(dst, r.rows[r.index])
	r.index++
	return nil
}
func newRecoveryScanFixture(t *testing.T) (*recoveryFixture, *recoveryScanDB) {
	t.Helper()
	f := newRecoveryFixture(t)
	d := &recoveryScanDB{recoveryDB: f.db, c: f.c, limit: 1}
	d.rows = [][]driver.Value{{int64(10), f.db.record.Manifest.Identity.ID}}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.a.c.Registry.DB = db
	return f, d
}

func TestRecoverySchedulingRecheckedUnderClaimLock(t *testing.T) {
	for _, delay := range []time.Duration{-time.Microsecond, 0, time.Microsecond, time.Minute} {
		t.Run(delay.String(), func(t *testing.T) {
			f := newRecoveryFixture(t)
			now := f.db.plan[7].values[0].(time.Time)
			f.db.observation.next = now.Add(delay)
			calls := 0
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) { calls++; return f.info(), nil }))
			if delay > 0 {
				if err != ErrConflict || calls != 0 || f.db.writes != 0 || len(f.db.audits) != 0 {
					t.Fatal("backoff bypass", err)
				}
			} else if err != nil || calls != 1 {
				t.Fatal("due boundary rejected", err)
			}
		})
	}
	f := newRecoveryFixture(t)
	calls := 0
	store := recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) { calls++; return ObjectInfo{}, ErrNotFound })
	if err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, store); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, store); err != ErrConflict || calls != 1 || f.db.writes != 2 {
		t.Fatal("immediate failed retry dispatched", err)
	}
}

func TestRecoveryBatchCommitsScanBeforeProvider(t *testing.T) {
	f, d := newRecoveryScanFixture(t)
	calls := 0
	batch, err := f.a.ReconcileBatch(f.ctx, 0, 1, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
		calls++
		if !d.scanCommitted || d.commits < 2 {
			t.Fatal("provider inside scan/claim transaction")
		}
		return f.info(), nil
	}))
	if err != nil || calls != 1 || batch.More || batch.AfterID != 10 || len(batch.Results) != 1 || batch.Results[0].Err != nil || f.db.record.State != "ready" {
		t.Fatal("batch failed", err, batch)
	}
}

func TestRecoveryBatchAdvancesPastRejectedCandidate(t *testing.T) {
	f, d := newRecoveryScanFixture(t)
	d.after = 4
	d.rows = append(d.rows, []driver.Value{int64(11), "sev_22222222-2222-4333-8444-555555555555"})
	f.policy.denyOwner = true
	store := recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
		t.Fatal("rejected owner reached provider")
		return ObjectInfo{}, nil
	})
	batch, err := f.a.ReconcileBatch(f.ctx, 4, 1, store)
	if err != nil || !batch.More || batch.AfterID != 10 || len(batch.Results) != 1 || batch.Results[0].Err != ErrDenied {
		t.Fatal("poison row starved cursor", err, batch)
	}
	d.after, d.rows = batch.AfterID, nil
	batch, err = f.a.ReconcileBatch(f.ctx, batch.AfterID, 1, store)
	if err != nil || batch.More || batch.AfterID != 10 || len(batch.Results) != 0 {
		t.Fatal("end of sweep invalid", err, batch)
	}
}

func TestRecoveryBatchRejectsInvalidScan(t *testing.T) {
	for _, kind := range []string{"no peer", "config", "query", "rows", "commit", "duplicate cursor", "backwards cursor", "bad id", "oversize", "zero limit", "high limit", "negative cursor"} {
		t.Run(kind, func(t *testing.T) {
			f, d := newRecoveryScanFixture(t)
			after, limit := int64(0), 1
			switch kind {
			case "no peer":
				f.ctx = context.Background()
			case "config":
				d.plan[2].values[0] = int64(999)
			case "query":
				d.queryErr = true
			case "rows":
				d.rowsErr = true
			case "commit":
				d.commitErr = true
			case "duplicate cursor":
				d.rows = append(d.rows, d.rows[0])
			case "backwards cursor":
				d.rows[0][0] = int64(0)
			case "bad id":
				d.rows[0][1] = "PRIVATE_INVALID_ID"
			case "oversize":
				d.rows = append(d.rows, []driver.Value{int64(11), d.rows[0][1]}, []driver.Value{int64(12), d.rows[0][1]})
			case "zero limit":
				limit = 0
			case "high limit":
				limit = 101
			case "negative cursor":
				after = -1
			}
			batch, err := f.a.ReconcileBatch(f.ctx, after, limit, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
				t.Fatal("invalid scan dispatched provider")
				return ObjectInfo{}, nil
			}))
			if err == nil || len(batch.Results) != 0 || d.writes != 0 || len(d.audits) != 0 || batch.AfterID != after {
				t.Fatal("invalid scan published work", err, batch)
			}
		})
	}
}

func TestRecoveryBatchRevalidatesStaleCandidates(t *testing.T) {
	for _, kind := range []string{"scheduled", "claim", "config", "owner deadline", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, d := newRecoveryScanFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			d.afterScan = func() {
				switch kind {
				case "scheduled":
					d.observation.next = time.Now().Add(time.Minute)
				case "claim":
					d.record.Claim = "other"
					d.record.ClaimUntil = time.Now().Add(time.Minute)
				case "config":
					d.plan[2].values[0] = int64(999)
				case "owner deadline":
					f.policy.deadline = time.Now().Add(time.Hour)
				case "cancel":
					cancel()
				}
			}
			batch, err := f.a.ReconcileBatch(ctx, 0, 1, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
				t.Fatal("stale scan authorized provider")
				return ObjectInfo{}, nil
			}))
			if kind == "cancel" {
				if err == nil || len(batch.Results) != 0 || batch.AfterID != 0 {
					t.Fatal("canceled scan exposed candidates", err, batch)
				}
			} else if err != nil || len(batch.Results) != 1 || batch.Results[0].Err == nil || batch.AfterID != 10 {
				t.Fatal("stale candidate accepted", err, batch)
			}
			if d.writes != 0 {
				t.Fatal("stale scan mutated evidence")
			}
		})
	}
}

func TestRecoveryBatchCancellationKeepsUnprocessedCursor(t *testing.T) {
	f, d := newRecoveryScanFixture(t)
	d.limit = 2
	d.rows = append(d.rows, []driver.Value{int64(11), "sev_22222222-2222-4333-8444-555555555555"})
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	calls := 0
	batch, err := f.a.ReconcileBatch(ctx, 0, 2, recoveryStatFunc(func(ctx context.Context, _ Ref) (ObjectInfo, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Second {
			t.Fatal("unbounded provider call")
		}
		cancel()
		return ObjectInfo{}, ErrUnavailable
	}))
	if err != ErrUnavailable || calls != 1 || batch.AfterID != 10 || !batch.More || len(batch.Results) != 1 || batch.Results[0].Err == nil {
		t.Fatal("cancellation skipped unprocessed candidate", err, batch)
	}
}
