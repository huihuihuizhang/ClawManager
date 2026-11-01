package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
)

// Actual in-process background writes complement the finite API/kubelet model.
// The application SQL writer uses the ORIGINAL mutation lease gate; the two
// physical-source models must join their writers BEFORE a termination ACK.
// This is still local code-call proof, never a physical kubelet certification.
type dOriginalBackground struct {
	f                *dOriginalSixPartTask
	ctx              context.Context
	mu               sync.Mutex
	processes        map[string]*dOriginalBackgroundProcess
	counters         map[string]*atomic.Uint64
	errors           []error
	denied           atomic.Uint64
	before           map[string]uint64
	heldHashes       map[string]string
	heldProgress     string
	heldObservations uint64
}
type dOriginalBackgroundProcess struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (f *dOriginalSixPartTask) startOriginalBackground(ctx context.Context, t *testing.T) {
	t.Helper()
	bg := &dOriginalBackground{f: f, ctx: ctx, processes: map[string]*dOriginalBackgroundProcess{}, counters: map[string]*atomic.Uint64{}, heldHashes: map[string]string{}}
	f.background = bg
	bg.start("application-mutations")
	bg.start("d-original-7")
	bg.start("d-platform-pod")
	t.Cleanup(func() {
		bg.stopAll()
		bg.mu.Lock()
		defer bg.mu.Unlock()
		for _, err := range bg.errors {
			t.Error("original background writer", err)
		}
	})
	until := time.NewTimer(5 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		bg.mu.Lock()
		ready := true
		for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
			ready = ready && bg.counters[id].Load() > 1
		}
		bg.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-until.C:
			t.Fatal("original background sources did not write")
		case <-tick.C:
		}
	}
}

func (b *dOriginalBackground) sourceFile(id string) string {
	if id == "d-original-7" {
		return filepath.Join(b.f.workspaceDirectories["instance_7_workspace"], "sessions", "original.json")
	}
	return filepath.Join(b.f.workspaceDirectories["team_20_workspace"], "artifacts", "original-result.json")
}
func (b *dOriginalBackground) start(id string) {
	b.mu.Lock()
	if b.processes[id] != nil {
		b.mu.Unlock()
		return
	}
	counter := b.counters[id]
	if counter == nil {
		counter = &atomic.Uint64{}
		b.counters[id] = counter
	}
	ctx, cancel := context.WithCancel(b.ctx)
	process := &dOriginalBackgroundProcess{cancel: cancel, done: make(chan struct{})}
	b.processes[id] = process
	b.mu.Unlock()
	go func() {
		defer close(process.done)
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var err error
			if id == "application-mutations" {
				gate := root.Gate{DB: b.f.db}
				lease, acquireErr := gate.AcquireMutation(ctx, b.f.service.Config.ApplicationScope, 5*time.Second)
				if errors.Is(acquireErr, root.ErrMaintenance) {
					b.denied.Add(1)
					continue
				}
				if acquireErr != nil {
					err = acquireErr
				} else {
					err = gate.WriteWithLease(ctx, lease, func(tx *sql.Tx) error {
						_, e := tx.ExecContext(ctx, "UPDATE team_members SET progress=MOD(progress+1,100) WHERE id=21")
						return e
					})
					releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					releaseErr := gate.ReleaseMutation(releaseCtx, lease)
					releaseCancel()
					err = errors.Join(err, releaseErr)
				}
			} else {
				err = os.WriteFile(b.sourceFile(id), []byte(fmt.Sprintf("{\"original_background_sequence\":%d}\n", counter.Load()+1)), 0600)
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				b.mu.Lock()
				b.errors = append(b.errors, fmt.Errorf("%s: %w", id, err))
				b.mu.Unlock()
				return
			}
			counter.Add(1)
		}
	}()
}
func (b *dOriginalBackground) stop(id string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	process := b.processes[id]
	b.mu.Unlock()
	if process == nil {
		return
	}
	process.cancel()
	<-process.done
	b.mu.Lock()
	if b.processes[id] == process {
		delete(b.processes, id)
	}
	b.mu.Unlock()
}
func (b *dOriginalBackground) stopAll() {
	for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
		b.stop(id)
	}
}

func (b *dOriginalBackground) checkHeld(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("original background writers were not installed")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.errors) != 0 || b.processes["d-original-7"] != nil || b.processes["d-platform-pod"] != nil {
		return fmt.Errorf("physical source background write survived original pause")
	}
	if len(b.counters) != 3 {
		return fmt.Errorf("original background counter set is incomplete")
	}
	for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
		if b.counters[id] == nil || b.counters[id].Load() < 2 {
			return fmt.Errorf("original background %s did not write before pause", id)
		}
	}
	var progress string
	if err := b.f.db.QueryRowContext(ctx, "SELECT CAST(progress AS CHAR) FROM team_members WHERE id=21").Scan(&progress); err != nil {
		return err
	}
	for _, id := range []string{"d-original-7", "d-platform-pod"} {
		raw, err := os.ReadFile(b.sourceFile(id))
		if err != nil {
			return err
		}
		digest := hash(raw)
		if old := b.heldHashes[id]; old != "" && old != digest {
			return fmt.Errorf("source %s changed inside original held window", id)
		}
		b.heldHashes[id] = digest
	}
	if b.heldProgress != "" && b.heldProgress != progress {
		return fmt.Errorf("application SQL write survived original held gate")
	}
	b.heldProgress = progress
	if b.before == nil {
		b.before = map[string]uint64{}
		for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
			b.before[id] = b.counters[id].Load()
		}
	}
	b.heldObservations++
	return nil
}
func (b *dOriginalBackground) checkResumed(ctx context.Context, t *testing.T) {
	t.Helper()
	if b == nil {
		t.Fatal("original background writers were not installed")
	}
	b.mu.Lock()
	complete := len(b.before) == 3 && len(b.counters) == 3 && len(b.heldHashes) == 2 && b.heldProgress != "" && b.heldObservations > 0
	for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
		complete = complete && b.before[id] > 1 && b.counters[id] != nil
	}
	for _, id := range []string{"d-original-7", "d-platform-pod"} {
		complete = complete && b.heldHashes[id] != ""
	}
	b.mu.Unlock()
	if !complete {
		t.Fatal("original held background observations were not complete before resume")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		b.mu.Lock()
		ready := len(b.errors) == 0
		for _, id := range []string{"application-mutations", "d-original-7", "d-platform-pod"} {
			ready = ready && b.processes[id] != nil && b.counters[id].Load() > b.before[id]
		}
		b.mu.Unlock()
		if ready && b.denied.Load() > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("original background writes did not resume after stop barrier")
		case <-tick.C:
		}
	}
}
