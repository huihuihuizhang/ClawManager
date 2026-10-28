package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type gcFreezeProtocolFixture struct {
	steps                           []string
	failure                         string
	connections, closed, admissions int
	cancel                          context.CancelFunc
	held                            bool
	identities                      int
}
type gcFreezeProtocolConnector struct{ s *gcFreezeProtocolFixture }

func (c gcFreezeProtocolConnector) Connect(context.Context) (driver.Conn, error) {
	c.s.connections++
	c.s.steps = append(c.s.steps, "connect")
	return &gcFreezeProtocolConn{s: c.s}, nil
}
func (c gcFreezeProtocolConnector) Driver() driver.Driver { return gcFreezeProtocolDriver{c.s} }

type gcFreezeProtocolDriver struct{ s *gcFreezeProtocolFixture }

func (d gcFreezeProtocolDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected legacy open")
}

type gcFreezeProtocolConn struct{ s *gcFreezeProtocolFixture }

func (c *gcFreezeProtocolConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *gcFreezeProtocolConn) Close() error {
	c.s.steps = append(c.s.steps, "close")
	c.s.closed++
	c.s.held = false
	return nil
}
func (c *gcFreezeProtocolConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected legacy begin")
}
func (c *gcFreezeProtocolConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.s.steps = append(c.s.steps, "begin")
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		return nil, errors.New("wrong isolation")
	}
	if c.s.failure == "begin" {
		return nil, errors.New("private-secret")
	}
	return &gcFreezeProtocolTx{s: c.s}, nil
}
func (c *gcFreezeProtocolConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	name := map[string]string{"LOCK INSTANCE FOR BACKUP": "lock", "UNLOCK INSTANCE": "unlock", "SET SESSION lock_wait_timeout = ?": "set_wait"}[q]
	if name == "" {
		return nil, errors.New("unexpected SQL")
	}
	c.s.steps = append(c.s.steps, name)
	if name == "lock" {
		c.s.held = true
	}
	if name == "unlock" {
		c.s.held = false
	}
	if c.s.failure == name {
		return nil, errors.New("private-secret")
	}
	return driver.RowsAffected(0), nil
}
func (c *gcFreezeProtocolConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if q == downloadGCFreezeSessionSQL {
		c.s.steps = append(c.s.steps, "identity")
		c.s.identities++
		account := "worker@%"
		if c.s.failure == "identity" {
			account = "wrong@%"
		}
		id := int64(41)
		if c.s.failure == "identity_changed" && c.s.identities > 1 {
			id = 42
		}
		return &gcFreezeProtocolRows{values: []driver.Value{"server", "database", account, "NONE", "+00:00", id}}, nil
	}
	if q == downloadGCFreezeHeldSQL {
		c.s.steps = append(c.s.steps, "held")
		n := int64(0)
		if c.s.held && c.s.failure != "held" {
			n = 1
		}
		if c.s.failure == "release_probe" && !c.s.held {
			return nil, errors.New("private-secret")
		}
		return &gcFreezeProtocolRows{values: []driver.Value{n}}, nil
	}
	return nil, errors.New("unexpected query")
}

type gcFreezeProtocolRows struct{ values []driver.Value }

func (r *gcFreezeProtocolRows) Columns() []string {
	names := make([]string, len(r.values))
	for i := range names {
		names[i] = "value"
	}
	return names
}
func (r *gcFreezeProtocolRows) Close() error { return nil }
func (r *gcFreezeProtocolRows) Next(out []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(out, r.values)
	r.values = nil
	return nil
}

type gcFreezeProtocolTx struct{ s *gcFreezeProtocolFixture }

func (tx *gcFreezeProtocolTx) Commit() error {
	tx.s.steps = append(tx.s.steps, "commit")
	if tx.s.failure == "commit" {
		return errors.New("private-secret")
	}
	if tx.s.failure == "cancel_after_commit" {
		tx.s.cancel()
	}
	return nil
}
func (tx *gcFreezeProtocolTx) Rollback() error {
	tx.s.steps = append(tx.s.steps, "rollback")
	if tx.s.failure == "rollback" {
		return errors.New("private-secret")
	}
	return nil
}
func gcFreezeProtocolConfig(s *gcFreezeProtocolFixture) downloadGCFreezeConfig {
	return downloadGCFreezeConfig{Connector: gcFreezeProtocolConnector{s}, Server: "server", Database: "database", Account: "worker@%", WaitSeconds: 2, Admit: func(context.Context, *sql.Conn) error {
		s.admissions++
		s.steps = append(s.steps, "admit")
		if s.failure == "admit" || s.failure == "second_admit" && s.admissions == 2 {
			return errors.New("private-secret")
		}
		return nil
	}}
}

func TestDownloadGCFreezeCandidateOrderAndFreshDisposal(t *testing.T) {
	s := &gcFreezeProtocolFixture{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := runDownloadGCFreeze(ctx, gcFreezeProtocolConfig(s), func(context.Context, *sql.Tx) error { s.steps = append(s.steps, "work"); return nil })
	want := []string{"connect", "identity", "admit", "identity", "set_wait", "lock", "held", "admit", "identity", "begin", "work", "held", "commit", "unlock", "held", "close"}
	if err != nil || !reflect.DeepEqual(s.steps, want) || out.Transaction != "committed" || out.Unlock != "confirmed" || !out.DiscardRequested || s.connections != 1 || s.closed != 1 {
		t.Fatalf("protocol order/outcome differs: %v %+v", s.steps, out)
	}
	// Each invocation creates/disposes its own pool/session. There is no old
	// session reuse, including temporary tables and modified session settings.
	_, err = runDownloadGCFreeze(ctx, gcFreezeProtocolConfig(s), func(context.Context, *sql.Tx) error { return nil })
	if err != nil || s.connections != 2 || s.closed != 2 {
		t.Fatal("private pool reused a previous physical session")
	}
}

func TestDownloadGCFreezeFinalizationFollowsTicket(t *testing.T) {
	for _, reject := range []bool{false, true} {
		s := &gcFreezeProtocolFixture{}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := runDownloadGCFreezeProtocol(ctx, gcFreezeProtocolConfig(s), func(context.Context, *sql.Tx) error { s.steps = append(s.steps, "work"); return nil }, func(context.Context, *sql.Tx) error {
			if s.steps[len(s.steps)-1] != "held" {
				t.Fatal("finalizer preceded final ticket")
			}
			s.steps = append(s.steps, "finalize")
			if reject {
				return errors.New("PRIVATE authority")
			}
			return nil
		})
		cancel()
		wantEnd := "committed"
		if reject {
			wantEnd = "rolled_back"
		}
		if (err != nil) != reject || out.Transaction != wantEnd || out.Unlock != "confirmed" || !out.DiscardRequested || s.connections != 1 || s.closed != 1 {
			t.Fatalf("finalizer transaction ownership differs: %v %+v", err, out)
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("finalizer cause leaked")
		}
	}
}

func TestDownloadGCFreezeCandidateFailures(t *testing.T) {
	for _, mode := range []string{"identity", "identity_changed", "admit", "second_admit", "set_wait", "lock", "held", "begin", "work", "rollback", "commit", "unlock", "release_probe", "cancel_work", "cancel_after_commit"} {
		t.Run(mode, func(t *testing.T) {
			s := &gcFreezeProtocolFixture{failure: mode}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.cancel = cancel
			out, err := runDownloadGCFreeze(ctx, gcFreezeProtocolConfig(s), func(context.Context, *sql.Tx) error {
				s.steps = append(s.steps, "work")
				if mode == "cancel_work" {
					cancel()
				}
				if mode == "work" || mode == "rollback" {
					return errors.New("private-secret")
				}
				return nil
			})
			if err == nil || strings.Contains(err.Error(), "private-secret") || s.connections != 1 || s.closed != 1 {
				t.Fatalf("failed protocol result/cleanup differs: %v %+v", s.steps, out)
			}
			has := func(step string) bool {
				for _, v := range s.steps {
					if v == step {
						return true
					}
				}
				return false
			}
			if mode == "commit" {
				if !errors.Is(err, errDownloadGCFreezeCommitUnknown) || out.Transaction != "unknown" || has("rollback") || has("unlock") {
					t.Fatal("ambiguous commit was retried, rolled back or unlocked")
				}
			}
			if mode == "rollback" {
				if !errors.Is(err, errDownloadGCFreezeRollbackUnknown) || has("unlock") {
					t.Fatal("unknown rollback unlocked session")
				}
			}
			if mode == "lock" || mode == "unlock" || mode == "release_probe" || mode == "cancel_after_commit" {
				if !errors.Is(err, errDownloadGCFreezeReleaseUnknown) || out.Unlock != "unknown" {
					t.Fatal("unknown lock release claimed confirmation")
				}
			}
			if mode == "cancel_after_commit" && out.Transaction != "committed" {
				t.Fatal("known commit lost after cancellation")
			}
			if mode == "second_admit" || mode == "held" {
				if has("begin") || has("work") {
					t.Fatal("work preceded exact lock/admission proof")
				}
			}
		})
	}
}

func TestDownloadGCFreezeCandidateClosedPreflight(t *testing.T) {
	for _, mode := range []string{"unbounded", "connector", "admission", "wait", "work", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s := &gcFreezeProtocolFixture{}
			c := gcFreezeProtocolConfig(s)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			work := func(context.Context, *sql.Tx) error { return nil }
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "connector":
				c.Connector = nil
			case "admission":
				c.Admit = nil
			case "wait":
				c.WaitSeconds = 6
			case "work":
				work = nil
			case "canceled":
				cancel()
			}
			out, err := runDownloadGCFreeze(ctx, c, work)
			if err == nil || s.connections != 0 || out.Transaction != "not_started" {
				t.Fatal("invalid protocol opened connection")
			}
		})
	}
}
