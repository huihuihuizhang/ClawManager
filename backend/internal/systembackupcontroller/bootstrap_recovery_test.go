package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real grant parser/probe with a mutable SQL transport, without
// requiring MySQL or borrowing another owner's provider implementation.
type recoveryGrantConnector struct{ revoked *atomic.Bool }

func (c recoveryGrantConnector) Connect(context.Context) (driver.Conn, error) {
	return recoveryGrantConn{revoked: c.revoked}, nil
}
func (recoveryGrantConnector) Driver() driver.Driver { return grantProbeDriver{} }

type recoveryGrantConn struct {
	grantProbeConn
	revoked *atomic.Bool
}

func (c recoveryGrantConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	grants := controllerTestGrants()
	if c.revoked.Load() {
		grants = grants[:1] // USAGE alone cannot admit a controller worker.
	}
	return (grantProbeConn{state: grantProbeConnector{user: "sbk_controller@%", role: "NONE", grants: grants}}).QueryContext(ctx, query, args)
}

func receiveRecovery[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for recovery transition")
		var zero T
		return zero
	}
}

func TestBootstrapSupervisorGrantRevocationAndRecoveryWithoutRestart(t *testing.T) {
	var revoked atomic.Bool
	db := sql.OpenDB(recoveryGrantConnector{revoked: &revoked})
	defer db.Close()
	probe := SQLControllerGrantProbe{DB: db, Schema: "clawmanager", User: "sbk_controller"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snapshot := BootstrapSnapshot{InstallationID: "installation_primary", ConfigVersion: 1}
	checker := &sequenceBootstrapChecker{results: []BootstrapCheckResult{{Snapshot: snapshot}}}
	ticks := make(chan time.Time)
	workTicks := make(chan struct{})
	started := make(chan int32, 4)
	failed := make(chan BootstrapSupervisorResult, 4)
	var starts, live atomic.Int32
	supervisor := BootstrapSupervisor{
		Checker: checker, CheckInterval: time.Second, WorkerStopTimeout: time.Second,
		Worker: func(ctx context.Context, _ BootstrapSnapshot) error {
			if err := probe.Check(ctx); err != nil {
				return err
			}
			if live.Add(1) != 1 {
				live.Add(-1)
				return errors.New("overlapping workers")
			}
			defer live.Add(-1)
			started <- starts.Add(1)
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-workTicks:
					if err := probe.Check(ctx); err != nil {
						return err
					}
				}
			}
		},
		OnResult: func(result BootstrapSupervisorResult) {
			if result.Err != nil {
				failed <- result
			}
		},
	}
	done := make(chan error, 1)
	go func() { done <- supervisor.runWithTicks(ctx, ticks) }()
	if receiveRecovery(t, started) != 1 {
		t.Fatal("first worker missing")
	}
	revoked.Store(true)
	workTicks <- struct{}{}
	if result := receiveRecovery(t, failed); result.WorkerRunning || BootstrapFailureCodeOf(result.Err) != BootstrapWorkerExited {
		t.Fatalf("revocation did not fail runtime: %+v", result)
	}
	if live.Load() != 0 {
		t.Fatal("revoked worker still running")
	}
	// An unchanged bootstrap snapshot must still retry admission on the next tick.
	ticks <- time.Time{}
	receiveRecovery(t, failed)
	select {
	case result := <-failed:
		t.Fatalf("worker retries spun without a new tick: %+v", result)
	case <-time.After(25 * time.Millisecond):
	}
	revoked.Store(false)
	ticks <- time.Time{}
	if receiveRecovery(t, started) != 2 || live.Load() != 1 {
		t.Fatal("same supervisor did not recover after grants restored")
	}
	cancel()
	if err := receiveRecovery(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown: %v", err)
	}
	if live.Load() != 0 {
		t.Fatal("worker survived shutdown")
	}
}

func TestBootstrapSupervisorRefusesReplacementUntilOldWorkerExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := BootstrapSnapshot{ConfigVersion: 1}
	second := BootstrapSnapshot{ConfigVersion: 2}
	checker := &sequenceBootstrapChecker{results: []BootstrapCheckResult{{Snapshot: first}, {Snapshot: second}}}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	exited := make(chan struct{})
	defer func() { close(release); receiveRecovery(t, exited) }()
	s := BootstrapSupervisor{
		Checker: checker, CheckInterval: time.Second, WorkerStopTimeout: 20 * time.Millisecond,
		Worker: func(context.Context, BootstrapSnapshot) error {
			started <- struct{}{}
			<-release // Deliberately uncooperative worker; no second policy may run.
			close(exited)
			return nil
		},
	}
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- s.runWithTicks(ctx, ticks) }()
	receiveRecovery(t, started)
	ticks <- time.Time{}
	if err := receiveRecovery(t, done); BootstrapFailureCodeOf(err) != BootstrapWorkerStopTimeout {
		t.Fatalf("wanted stop timeout, got %v", err)
	}
	select {
	case <-started:
		t.Fatal("started replacement while old worker was alive")
	default:
	}
}

func TestBootstrapSupervisorRechecksAfterBootstrapDatabaseFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker := &sequenceBootstrapChecker{results: []BootstrapCheckResult{
		{Err: bootstrapFailure(BootstrapMigrationQuery, errors.New("database unavailable"))},
		{Snapshot: BootstrapSnapshot{ConfigVersion: 1}},
	}}
	results := make(chan BootstrapSupervisorResult, 3)
	started := make(chan struct{}, 1)
	s := BootstrapSupervisor{Checker: checker, CheckInterval: time.Second, WorkerStopTimeout: time.Second,
		OnResult: func(result BootstrapSupervisorResult) { results <- result },
		Worker: func(ctx context.Context, _ BootstrapSnapshot) error {
			started <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- s.runWithTicks(ctx, ticks) }()
	if result := receiveRecovery(t, results); result.Err == nil || result.WorkerRunning {
		t.Fatal("database failure admitted worker")
	}
	ticks <- time.Time{}
	receiveRecovery(t, started)
	if result := receiveRecovery(t, results); result.Err != nil || !result.WorkerRunning {
		t.Fatal("database recovery did not restore runtime")
	}
	cancel()
	if err := receiveRecovery(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
