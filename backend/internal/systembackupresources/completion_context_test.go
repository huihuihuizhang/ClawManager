package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

// Cancel inside the driver's Commit, after database/sql's pre-commit context
// check. This models a driver that finishes successfully after cancellation.
type completionConnector struct {
	state  *countFixture
	finish func()
}

func (c completionConnector) Connect(context.Context) (driver.Conn, error) {
	return &completionConn{countConn: &countConn{c.state}, finish: c.finish}, nil
}
func (c completionConnector) Driver() driver.Driver { return countDriver{c.state} }

type completionConn struct {
	*countConn
	finish func()
}

func (c *completionConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.countConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return completionTx{Tx: tx, finish: c.finish}, nil
}

type completionTx struct {
	driver.Tx
	finish func()
}

func (tx completionTx) Commit() error {
	err := tx.Tx.Commit()
	tx.finish()
	return err
}

func completionDB(t *testing.T, state *countFixture, finish func()) *sql.DB {
	t.Helper()
	db := sql.OpenDB(completionConnector{state: state, finish: finish})
	t.Cleanup(func() { db.Close() })
	return db
}

func TestResourcesCountCompletionContext(t *testing.T) {
	for _, mode := range []string{"normal", "canceled", "deadline", "commit_error", "collect_canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			state := newCountFixture()
			finish := func() {}
			if mode != "normal" {
				finish = func() { cancel(context.Canceled) }
			}
			// WithDeadlineCause's callback is timer driven; WithCancelCause does
			// not change Err to DeadlineExceeded. Use a deadline context whose
			// parent is deterministically advanced inside Commit instead.
			if mode == "deadline" {
				ctx = &completionDeadlineContext{Context: ctx}
			}
			if mode == "commit_error" {
				state.failure = "commit"
			}
			collector := SQLCountCollector{DB: completionDB(t, state, finish)}
			var snapshot SourceSnapshot
			var err error
			if mode == "collect_canceled" {
				snapshot.Tables, err = collector.Collect(ctx, frozenRegistryBytes(t))
			} else {
				snapshot, err = collector.CollectSnapshot(ctx, frozenRegistryBytes(t))
			}
			if state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 2*len(resourceTables) || !state.begin.ReadOnly || state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatalf("changed transaction boundary: %+v", state)
			}
			switch mode {
			case "normal":
				if err != nil || len(snapshot.Tables) != len(resourceTables) || snapshot.AuditMaxID == nil {
					t.Fatalf("normal result lost: %+v %v", snapshot, err)
				}
			case "commit_error":
				if err == nil || !strings.Contains(err.Error(), "commit resources count snapshot: injected commit failure") || snapshot.Tables != nil || snapshot.AuditMaxID != nil {
					t.Fatalf("commit error lost: %+v %v", snapshot, err)
				}
			default:
				if !errors.Is(err, ctx.Err()) || err == nil || snapshot.Tables != nil || snapshot.AuditMaxID != nil {
					t.Fatalf("late snapshot returned: %+v %v", snapshot, err)
				}
			}
		})
	}
}

// Preserve Done/Value behavior while reporting deterministic deadline expiry
// when its parent is canceled by the driver; no sleeps or timing thresholds.
type completionDeadlineContext struct{ context.Context }

func (c *completionDeadlineContext) Err() error {
	if c.Context.Err() != nil {
		return context.DeadlineExceeded
	}
	return nil
}

type completionCaptureProof func(context.Context, CaptureSnapshotEvidence, CaptureSnapshotEvidence) error

func (f completionCaptureProof) VerifyCapture(ctx context.Context, source, dump CaptureSnapshotEvidence) error {
	return f(ctx, source, dump)
}

func TestResourcesProofCompletionContext(t *testing.T) {
	for _, mode := range []string{"normal", "mismatch", "canceled", "canceled_mismatch", "deadline", "proof_error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				ctx = &completionDeadlineContext{Context: ctx}
			}
			source, dump := verifierEvidence(), verifierEvidence()
			if mode == "mismatch" || mode == "canceled_mismatch" {
				dump.Snapshot.Tables[1].Rows++
			}
			proofErr := errors.New("capture rejected")
			calls := 0
			proof := completionCaptureProof(func(context.Context, CaptureSnapshotEvidence, CaptureSnapshotEvidence) error {
				calls++
				if mode != "normal" && mode != "mismatch" {
					cancel()
				}
				if mode == "proof_error" {
					return proofErr
				}
				return nil
			})
			checks, err := VerifyBackupSnapshot(ctx, frozenRegistryBytes(t), source, dump, proof)
			if calls != 1 {
				t.Fatalf("proof calls=%d", calls)
			}
			switch mode {
			case "normal", "mismatch":
				if err != nil || len(checks) != len(resourceTables)+3 {
					t.Fatalf("normal checks lost: %v %v", checks, err)
				}
				failed := 0
				for _, check := range checks {
					if check.Status == "failed" {
						failed++
						if check.ID != "resources.table_count.egress_private_exceptions" || check.FailureCategory != "validation_failed" {
							t.Fatalf("wrong mismatch: %+v", check)
						}
					}
				}
				if (mode == "mismatch") != (failed == 1) || mode == "normal" && failed != 0 {
					t.Fatalf("failed=%d in %s", failed, mode)
				}
			case "proof_error":
				if !errors.Is(err, proofErr) || checks != nil {
					t.Fatalf("proof error lost: %v %v", checks, err)
				}
			default:
				if err == nil || !errors.Is(err, ctx.Err()) || checks != nil {
					t.Fatalf("late checks returned: %v %v", checks, err)
				}
			}
		})
	}
}
