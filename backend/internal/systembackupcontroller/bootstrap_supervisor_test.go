package systembackupcontroller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type sequenceBootstrapChecker struct {
	mu      sync.Mutex
	results []BootstrapCheckResult
	calls   int
}

type workerEvent struct {
	kind    string
	version uint64
}

func (c *sequenceBootstrapChecker) Check(context.Context, BootstrapRequirements) (BootstrapSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.calls
	c.calls++
	if index >= len(c.results) {
		index = len(c.results) - 1
	}
	return c.results[index].Snapshot, c.results[index].Err
}

func TestBootstrapSupervisorStopsOldWorkerBeforeConfigRestart(t *testing.T) {
	first := BootstrapSnapshot{
		InstallationID:       "installation_primary",
		ConfigVersion:        1,
		ConfigEnabled:        true,
		EnvironmentEnabled:   true,
		EffectiveEnabled:     true,
		MatrixKey:            "k8s-cluster",
		Policy:               LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: 10 * time.Second},
		MigrationCatalogHash: ContractMigrationCatalogHash,
	}
	second := first
	second.ConfigVersion = 2
	second.Policy.ReconcileInterval = 5 * time.Second
	checker := &sequenceBootstrapChecker{results: []BootstrapCheckResult{{Snapshot: first}, {Snapshot: second}}}

	events := make(chan workerEvent, 4)
	supervisor := BootstrapSupervisor{
		Checker:           checker,
		Requirements:      validBootstrapRequirements(),
		CheckInterval:     DefaultBootstrapCheckInterval,
		WorkerStopTimeout: time.Second,
		Worker: func(ctx context.Context, snapshot BootstrapSnapshot) error {
			events <- workerEvent{kind: "start", version: snapshot.ConfigVersion}
			<-ctx.Done()
			events <- workerEvent{kind: "stop", version: snapshot.ConfigVersion}
			return ctx.Err()
		},
	}
	ticks := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.runWithTicks(ctx, ticks) }()

	wantEvent(t, events, workerEvent{kind: "start", version: 1})
	ticks <- time.Time{}
	wantEvent(t, events, workerEvent{kind: "stop", version: 1})
	wantEvent(t, events, workerEvent{kind: "start", version: 2})
	cancel()
	wantEvent(t, events, workerEvent{kind: "stop", version: 2})
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor error = %v", err)
	}
}

func wantEvent(t *testing.T, events <-chan workerEvent, want workerEvent) {
	t.Helper()
	select {
	case got := <-events:
		if got != want {
			t.Fatalf("event = %#v, want %#v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %#v", want)
	}
}

func TestBootstrapSupervisorCancelsWorkerWhenGateFails(t *testing.T) {
	snapshot := BootstrapSnapshot{
		InstallationID:       "installation_primary",
		ConfigVersion:        1,
		Policy:               LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: 10 * time.Second},
		MigrationCatalogHash: ContractMigrationCatalogHash,
	}
	checker := &sequenceBootstrapChecker{results: []BootstrapCheckResult{
		{Snapshot: snapshot},
		{Err: bootstrapFailure(BootstrapMigrationsMissing, errors.New("pending migration"))},
	}}
	started := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	var resultCodes []BootstrapFailureCode
	var resultMu sync.Mutex
	supervisor := BootstrapSupervisor{
		Checker:           checker,
		Requirements:      validBootstrapRequirements(),
		CheckInterval:     DefaultBootstrapCheckInterval,
		WorkerStopTimeout: time.Second,
		Worker: func(ctx context.Context, _ BootstrapSnapshot) error {
			started <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			return ctx.Err()
		},
		OnResult: func(result BootstrapSupervisorResult) {
			if result.Err != nil {
				resultMu.Lock()
				resultCodes = append(resultCodes, BootstrapFailureCodeOf(result.Err))
				resultMu.Unlock()
			}
		},
	}
	ticks := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.runWithTicks(ctx, ticks) }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}
	ticks <- time.Time{}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("worker was not canceled after gate failure")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor error = %v", err)
	}
	resultMu.Lock()
	defer resultMu.Unlock()
	if len(resultCodes) != 1 || resultCodes[0] != BootstrapMigrationsMissing {
		t.Fatalf("result codes = %#v", resultCodes)
	}
}
