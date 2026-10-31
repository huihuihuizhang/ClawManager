package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// Named SQL-driver boundary fixtures exercise the real heartbeat coordinator,
// including an in-flight Exec canceled by shutdown. They are not SQL authority
// or claim-acquisition evidence.
type shutdownRenewState struct {
	mode    string
	started chan struct{}
	once    sync.Once
}
type shutdownRenewConnector struct{ state *shutdownRenewState }

func (x shutdownRenewConnector) Connect(context.Context) (driver.Conn, error) {
	return shutdownRenewConn{x.state}, nil
}
func (x shutdownRenewConnector) Driver() driver.Driver { return shutdownRenewDriver{} }

type shutdownRenewDriver struct{}

func (shutdownRenewDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected Open")
}

type shutdownRenewConn struct{ state *shutdownRenewState }

func (shutdownRenewConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (shutdownRenewConn) Close() error              { return nil }
func (shutdownRenewConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected Begin") }
func (x shutdownRenewConn) ExecContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	x.state.once.Do(func() { close(x.state.started) })
	switch x.state.mode {
	case "zero-rows":
		return driver.RowsAffected(0), nil
	case "zero-rows-at-shutdown":
		<-ctx.Done()
		return driver.RowsAffected(0), nil
	case "database-error-at-shutdown":
		<-ctx.Done()
		return nil, errors.New("named database failure at shutdown")
	case "database-error":
		return nil, errors.New("named independent database failure")
	default:
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func TestExecutionHeartbeatShutdownPreservesRealRenewalFailures(t *testing.T) {
	for _, mode := range []string{"callback-return", "parent-stop", "callback-error", "zero-rows", "database-error", "zero-rows-at-shutdown", "database-error-at-shutdown"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			state := &shutdownRenewState{mode: mode, started: make(chan struct{})}
			db := sql.OpenDB(shutdownRenewConnector{state})
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			a := d.Authority{InstallationID: "heartbeat-fixture", ClaimOwner: "heartbeat-owner", TaskPublicID: "sbk_heartbeat", ClaimRowVersion: 9}
			store := SQLExecutionWorkStore{Queue: SQLExecutionQueue{DB: db, InstallationID: a.InstallationID, Owner: a.ClaimOwner, Policy: LeasePolicy{TTL: 15 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}}}
			callbackErr := errors.New("named callback failure")
			err := store.RunWithExecutionHeartbeat(ctx, a, func(active context.Context) error {
				select {
				case <-state.started:
				case <-ctx.Done():
					return ctx.Err()
				}
				switch mode {
				case "zero-rows", "database-error":
					<-active.Done()
					return nil
				case "parent-stop":
					cancel()
					<-active.Done()
					return nil
				case "callback-error":
					return callbackErr
				default:
					return nil
				}
			})
			switch mode {
			case "zero-rows", "database-error", "zero-rows-at-shutdown", "database-error-at-shutdown":
				if !errors.Is(err, ErrClaimLost) {
					t.Fatalf("real renewal failure lost: %v", err)
				}
			case "callback-error":
				if !errors.Is(err, callbackErr) {
					t.Fatalf("callback error changed: %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("cooperative shutdown became claim loss: %v", err)
				}
			}
		})
	}
}
