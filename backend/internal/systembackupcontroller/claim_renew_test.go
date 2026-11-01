package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Named protocol model for the old coordinator/CAS tests. Actual lock waits,
// delivered SQL clocks and durable rollback are covered by native MySQL tests.
func claimModelDB(t *testing.T, backend Executor) *sql.DB {
	t.Helper()
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	db := sql.OpenDB(claimModelConnector{&claimModelState{backend: backend, now: now, until: now.Add(DefaultClaimTTL)}})
	t.Cleanup(func() { db.Close() })
	return db
}

type claimModelState struct {
	backend               Executor
	now, until, heartbeat time.Time
}
type claimModelConnector struct{ state *claimModelState }

func (c claimModelConnector) Driver() driver.Driver { return shutdownRenewDriver{} }
func (c claimModelConnector) Connect(context.Context) (driver.Conn, error) {
	return &claimModelConn{state: c.state}, nil
}

type claimModelConn struct{ state *claimModelState }

func (*claimModelConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (*claimModelConn) Close() error { return nil }
func (c *claimModelConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *claimModelConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	tx := &claimModelTx{state: c.state, before: *c.state}
	if s, ok := c.state.backend.(*takeoverStore); ok {
		copy := *s
		tx.takeover = &copy
	}
	return tx, nil
}

type claimModelTx struct {
	state    *claimModelState
	before   claimModelState
	takeover *takeoverStore
}

func (*claimModelTx) Commit() error { return nil }
func (t *claimModelTx) Rollback() error {
	*t.state = t.before
	if t.takeover != nil {
		*t.state.backend.(*takeoverStore) = *t.takeover
	}
	return nil
}
func (c *claimModelConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	now, until := c.state.now, c.state.until
	if s, ok := c.state.backend.(*takeoverStore); ok {
		now, until = s.now, s.leaseUntil
	}
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return &claimReceiptRows{values: []driver.Value{now}}, nil
	}
	var heartbeat driver.Value
	if !strings.Contains(q, ",NULL") && !c.state.heartbeat.IsZero() {
		heartbeat = c.state.heartbeat
	}
	if strings.Contains(q, ",UTC_TIMESTAMP(6),") {
		return &claimReceiptRows{values: []driver.Value{until, now, heartbeat}}, nil
	}
	return &claimReceiptRows{values: []driver.Value{until, heartbeat, now}}, nil
}
func (c *claimModelConn) ExecContext(ctx context.Context, q string, named []driver.NamedValue) (driver.Result, error) {
	args := make([]any, len(named))
	for i, v := range named {
		args[i] = v.Value
	}
	if strings.Contains(q, "SET controller_owner = ?") {
		args[4] = uint64(args[4].(int64))
	} else if len(args) > 3 {
		args[3] = uint64(args[3].(int64))
	}
	result, err := c.state.backend.ExecContext(ctx, q, args...)
	if err == nil && strings.Contains(q, "GREATEST(") {
		now := c.state.now
		if s, ok := c.state.backend.(*takeoverStore); ok {
			now = s.now
		}
		c.state.heartbeat = now
		until := now.Add(time.Duration(args[0].(int64)) * time.Microsecond)
		if until.After(c.state.until) {
			c.state.until = until
		}
	}
	return result, err
}

func TestRenewRejectsExecOnlyAndCallerOwnedTransactionBeforeEffects(t *testing.T) {
	exec := &recordedExec{rows: 1}
	token := ClaimToken{Target: validBackupTarget(), Owner: "controller:pod-1", RowVersion: 7}
	if got, err := RenewClaimInInstallation(context.Background(), exec, "installation_test", token, validPolicy()); !errors.Is(err, ErrClaimTransactionRequired) || !errors.Is(err, ErrClaimLost) || got != (ClaimToken{}) || len(exec.queries) != 0 {
		t.Fatal("unsafe Exec-only renewal", got, err, exec.queries)
	}
	db := claimModelDB(t, exec)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if got, err := RenewClaimInInstallation(context.Background(), tx, "installation_test", token, validPolicy()); !errors.Is(err, ErrClaimTransactionRequired) || !errors.Is(err, ErrClaimLost) || got != (ClaimToken{}) || len(exec.queries) != 0 {
		t.Fatal("caller-owned transaction renewal", got, err, exec.queries)
	}
}

func TestRenewRetainsWholeMicrosecondIntervalContract(t *testing.T) {
	for _, extra := range []time.Duration{time.Microsecond, time.Nanosecond} {
		t.Run(extra.String(), func(t *testing.T) {
			exec := &recordedExec{rows: 1}
			policy := validPolicy()
			policy.TTL += extra
			if err := policy.Validate(); err != nil {
				t.Fatal(err)
			}
			token := ClaimToken{Target: validBackupTarget(), Owner: "controller:pod-1", RowVersion: 7}
			got, err := RenewClaimInInstallation(context.Background(), claimModelDB(t, exec), "installation_test", token, policy)
			if extra == time.Nanosecond {
				if err == nil || !strings.Contains(err.Error(), "whole number of microseconds") || got != (ClaimToken{}) || len(exec.queries) != 0 {
					t.Fatal("submicrosecond interval changed its preexisting SQL refusal", got, err, exec.queries)
				}
			} else if err != nil || got.RowVersion != 8 || exec.args[0][0] != policy.TTL.Microseconds() {
				t.Fatal("microsecond interval not preserved", got, err, exec.args)
			}
		})
	}
}
