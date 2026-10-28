package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The original collector, hint scan, guards and group SQL run unchanged. Only
// the transport's ROLLBACK response is replaced after the scripted rollback.
// This proves error/cursor handling, not MySQL cleanup or backup-lock release.
type gcRollbackFaultConnector struct {
	inner                             driver.Connector
	mu                                sync.Mutex
	failAt                            int
	begun, commits, rollbacks, closed int
}
type gcRollbackFaultConn struct {
	driver.Conn
	pool *gcRollbackFaultConnector
}
type gcRollbackFaultTx struct {
	driver.Tx
	pool *gcRollbackFaultConnector
	fail bool
}

func (p *gcRollbackFaultConnector) Driver() driver.Driver { return p.inner.Driver() }
func (p *gcRollbackFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := p.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &gcRollbackFaultConn{c, p}, nil
}
func (c *gcRollbackFaultConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	c.pool.mu.Lock()
	c.pool.begun++
	fail := c.pool.begun == c.pool.failAt
	c.pool.mu.Unlock()
	return &gcRollbackFaultTx{tx, c.pool, fail}, nil
}
func (c *gcRollbackFaultConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}
func (c *gcRollbackFaultConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func (c *gcRollbackFaultConn) Close() error {
	c.pool.mu.Lock()
	c.pool.closed++
	c.pool.mu.Unlock()
	return c.Conn.Close()
}
func (c *gcRollbackFaultConn) ResetSession(ctx context.Context) error {
	if reset, ok := c.Conn.(driver.SessionResetter); ok {
		return reset.ResetSession(ctx)
	}
	return nil
}
func (c *gcRollbackFaultConn) IsValid() bool {
	if valid, ok := c.Conn.(driver.Validator); ok {
		return valid.IsValid()
	}
	return true
}
func (tx *gcRollbackFaultTx) Commit() error {
	tx.pool.mu.Lock()
	tx.pool.commits++
	tx.pool.mu.Unlock()
	return tx.Tx.Commit()
}
func (tx *gcRollbackFaultTx) Rollback() error {
	tx.pool.mu.Lock()
	tx.pool.rollbacks++
	tx.pool.mu.Unlock()
	err := tx.Tx.Rollback()
	if tx.fail {
		return errors.New("PRIVATE rollback response lost")
	}
	return err
}
func installGCRollbackFault(t *testing.T, f *retentionGCFixture, inner driver.Connector, failAt int) *gcRollbackFaultConnector {
	t.Helper()
	p := &gcRollbackFaultConnector{inner: inner, failAt: failAt}
	db := sql.OpenDB(p)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	f.s.c.Registry.DB = db
	return p
}
func denyGCRollbackFixture(f *retentionGCFixture, late bool) {
	if !late {
		f.policy.denyLock = true
		return
	}
	f.policy.onCheck = func(n int) {
		if n == 2 {
			f.policy.denyGuard = true
		}
	}
}

func TestDownloadRetentionGCRollbackOutcome(t *testing.T) {
	for _, mode := range []string{"known_early", "unknown_early", "known_late", "unknown_late", "commit", "commit_unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			before := gcConnectionGroupSnapshot(f.d)
			unknown := strings.HasPrefix(mode, "unknown_")
			failAt := 0
			if unknown {
				failAt = 1
			}
			p := installGCRollbackFault(t, f, f.d, failAt)
			committing := mode == "commit" || mode == "commit_unknown"
			if committing {
				f.d.commitUnknown = mode == "commit_unknown"
			} else {
				denyGCRollbackFixture(f, strings.HasSuffix(mode, "late"))
			}
			err := f.s.Collect(f.ctx, f.operation)
			want := error(ErrDenied)
			if unknown {
				want = ErrDownloadRetentionGCRollbackUnknown
			}
			if mode == "commit" {
				want = nil
			}
			if mode == "commit_unknown" {
				want = ErrDownloadRetentionGCCommitUnknown
			}
			if err != want || err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("wrong transaction outcome: got %v want %v", err, want)
			}
			if committing {
				if p.commits != 1 || p.rollbacks != 0 || f.d.commits != f.commits+1 || len(f.d.stone) != 23 || len(f.d.m.op) != 0 {
					t.Fatal("commit was retried or claimed rolled back")
				}
			} else {
				if p.commits != 0 || p.rollbacks != 1 || f.d.commits != f.commits || len(f.d.stone) != 0 || !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) {
					t.Fatal("original group was not atomically restored")
				}
				wantWrites := 0
				if strings.HasSuffix(mode, "late") {
					wantWrites = 7
				}
				if len(f.d.writes) != wantWrites {
					t.Fatal("rollback did not cover the expected write boundary", len(f.d.writes))
				}
			}
			if p.begun != 1 || p.closed != 1 || f.d.active || f.s.c.Registry.DB.Stats().OpenConnections != 0 {
				t.Fatal("collector session was reused or left active")
			}
		})
	}
}

func TestDownloadRetentionGCBatchRollbackOutcome(t *testing.T) {
	for _, mode := range []string{"known_early", "unknown_early", "known_late", "unknown_late"} {
		t.Run(mode, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			before := gcConnectionGroupSnapshot(f.d)
			unknown := strings.HasPrefix(mode, "unknown_")
			failAt := 0
			if unknown {
				failAt = 2
			}
			p := installGCRollbackFault(t, f, m, failAt)
			denyGCRollbackFixture(f, strings.HasSuffix(mode, "late"))
			result, err := f.s.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, 1)
			if unknown {
				if err != ErrDownloadRetentionGCRollbackUnknown || !result.RollbackUnknown || result.Cursor.AfterID != 0 || result.Rejected != 0 {
					t.Fatal("unknown rollback was counted as rejection or advanced the cursor", result, err)
				}
			} else if err != nil || result.RollbackUnknown || result.Cursor.AfterID != 73 || result.Rejected != 1 {
				t.Fatal("known rollback did not preserve normal rejection", result, err)
			}
			if result.Examined != 1 || result.Collected != 0 || result.CommitUnknown || result.EndOfRange || result.Cursor.ThroughID != 74 || m.scanRollbacks != 1 || p.begun != 2 || p.commits != 0 || p.rollbacks != 2 || p.closed != 1 || f.d.active || f.s.c.Registry.DB.Stats().OpenConnections != 0 {
				t.Fatal("batch retried or lost its exact transaction boundary", result, err)
			}
			if !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) || len(f.d.stone) != 0 {
				t.Fatal("batch changed the original group after rollback")
			}
		})
	}
}

func TestDownloadGCConnectionRollbackOutcome(t *testing.T) {
	for _, mode := range []string{"rollback", "rollback_error", "already_rolled_back", "canceled", "commit", "unknown_commit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, p := gcConnectionFixture(t, ctx)
			p.mode = mode
			owned, _, err := beginDownloadGCConnection(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { owned.close() })
			if mode == "commit" || mode == "unknown_commit" {
				err = owned.commit()
				if (err == nil) != (mode == "commit") {
					t.Fatal("commit response misclassified", err)
				}
				if owned.commit() != ErrDownloadRetentionGCCommitUnknown || p.commits != 1 {
					t.Fatal("commit attempt retried")
				}
			}
			if mode == "already_rolled_back" {
				if err = owned.tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "canceled" {
				cancel()
				select {
				case <-p.rolled:
				case <-time.After(5 * time.Second):
					t.Fatal("automatic rollback did not run")
				}
			}
			err = owned.close()
			wantUnknown := mode == "rollback_error" || mode == "already_rolled_back" || mode == "canceled"
			if wantUnknown && err != ErrDownloadRetentionGCRollbackUnknown || !wantUnknown && err != nil {
				t.Fatal("unobserved rollback acknowledged", mode, err)
			}
			if again := owned.close(); again != err || p.closed != 1 || r.DB.Stats().OpenConnections != 0 {
				t.Fatal("close retried or erased an unknown outcome", again, err)
			}
			if mode == "commit" || mode == "unknown_commit" {
				if p.rollbacks != 0 {
					t.Fatal("commit claimed a rollback")
				}
			} else if p.rollbacks != 1 {
				t.Fatal("rollback retried", p.rollbacks)
			}
		})
	}
}

func TestDownloadGCBatchRollbackUnknownBeforeCancellation(t *testing.T) {
	for _, mode := range []string{"plain", "wrapped", "canceled", "wrapped_canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []string
			candidates := []downloadGCBatchCandidate{{1, "first"}, {3, "uncertain"}, {5, "never"}}
			result, err := runDownloadGCBatch(ctx, DownloadRetentionGCBatchResult{Cursor: DownloadRetentionGCBatchCursor{ThroughID: 9}}, candidates, false, func(_ context.Context, operation string) error {
				calls = append(calls, operation)
				if len(calls) == 1 {
					return nil
				}
				if strings.HasSuffix(mode, "canceled") {
					cancel()
				}
				if strings.HasPrefix(mode, "wrapped") {
					return fmt.Errorf("PRIVATE transport detail: %w", ErrDownloadRetentionGCRollbackUnknown)
				}
				return ErrDownloadRetentionGCRollbackUnknown
			})
			if err != ErrDownloadRetentionGCRollbackUnknown || !result.RollbackUnknown || result.CommitUnknown || result.Examined != 2 || result.Collected != 1 || result.Rejected != 0 || result.Cursor.AfterID != 1 || result.EndOfRange || !reflect.DeepEqual(calls, []string{"first", "uncertain"}) {
				t.Fatal("uncertain rollback was hidden by cancellation, leaked, retried or advanced", result, err, calls)
			}
		})
	}
}
