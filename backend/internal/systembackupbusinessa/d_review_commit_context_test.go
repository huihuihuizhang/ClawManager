package systembackupbusinessa

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

// Reproduce a successful driver acknowledgement after the request was
// canceled inside Commit, beyond database/sql's pre-Commit context check.
type dReviewCommitConnector struct {
	state *countState
	after func()
	err   error
}

func (c *dReviewCommitConnector) Driver() driver.Driver { return countConnector{c.state}.Driver() }
func (c *dReviewCommitConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := (countConnector{c.state}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &dReviewCommitConn{Conn: conn, probe: c}, nil
}

type dReviewCommitConn struct {
	driver.Conn
	probe *dReviewCommitConnector
}

func (c *dReviewCommitConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return dReviewCommitTx{Tx: tx, probe: c.probe}, nil
}

func (c *dReviewCommitConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

type dReviewCommitTx struct {
	driver.Tx
	probe *dReviewCommitConnector
}

func (tx dReviewCommitTx) Commit() error {
	err := tx.Tx.Commit()
	if tx.probe.after != nil {
		tx.probe.after()
	}
	if err != nil {
		return err
	}
	return tx.probe.err
}

func TestDReviewABusinessReadCommitBoundary(t *testing.T) {
	for _, entry := range []string{"capture_counts", "restore_verifier"} {
		t.Run(entry, func(t *testing.T) {
			for _, mode := range []string{"healthy", "canceled_commit", "commit_error"} {
				t.Run(mode, func(t *testing.T) {
					scope, expected := restoreFixture(t)
					state, proof := &countState{}, &restoreProofFixture{}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					probe := &dReviewCommitConnector{state: state}
					if mode == "canceled_commit" {
						probe.after = cancel
					} else if mode == "commit_error" {
						probe.err = errors.New("private commit acknowledgement failure")
					}
					db := sql.OpenDB(probe)
					defer db.Close()
					var got any
					var err error
					queries := 31
					if entry == "capture_counts" {
						got, err = (SQLCountCollector{DB: db}).CollectSnapshot(ctx, scope)
					} else {
						queries = 40
						got, err = (SQLRestoreVerifier{DB: db, Proof: proof}).VerifyRestoreTarget(ctx, scope, expected, "sev_restored")
						if proof.starts != 1 || proof.rechecks != 1 {
							t.Fatal("probe did not complete original target proof checks")
						}
					}
					if state.commits != 1 || state.rollbacks != 0 || len(state.queries) != queries || !state.begin.ReadOnly || state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
						t.Fatal("probe changed SQL, read-only RR, commit count or rollback outcome")
					}
					if mode == "healthy" {
						if err != nil || reflect.ValueOf(got).IsZero() {
							t.Fatal("healthy read rejected", err)
						}
					} else if err == nil || !reflect.ValueOf(got).IsZero() {
						t.Error("late or uncertain commit returned capture counts or restore checks", err)
					}
					if mode == "canceled_commit" && (ctx.Err() != context.Canceled || !errors.Is(err, context.Canceled)) {
						t.Error("original cancellation cause was lost", err)
					}
				})
			}
		})
	}
}

func TestDReviewARestoreMismatchAndCanceledResult(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "live_mismatch"
		if canceled {
			name = "canceled_mismatch_commit"
		}
		t.Run(name, func(t *testing.T) {
			scope, expected := restoreFixture(t)
			state := &countState{counts: map[string]int64{"users": 3}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probe := &dReviewCommitConnector{state: state}
			if canceled {
				probe.after = cancel
			}
			db := sql.OpenDB(probe)
			defer db.Close()
			checks, err := (SQLRestoreVerifier{DB: db, Proof: &restoreProofFixture{}}).VerifyRestoreTarget(ctx, scope, expected, "sev_restored")
			if state.commits != 1 || state.rollbacks != 0 {
				t.Fatal("read-only commit outcome changed")
			}
			if canceled {
				if !errors.Is(err, context.Canceled) || !reflect.ValueOf(checks).IsZero() || errors.Is(err, ErrRestoreNormalizationMismatch) {
					t.Error("expired verification returned partial mismatch evidence", err)
				}
			} else if !errors.Is(err, ErrRestoreNormalizationMismatch) || len(checks.Users) != 11 || len(checks.AIGateway) != 14 {
				t.Fatal("completed mismatch lost its original bounded evidence", err)
			}
		})
	}
}
