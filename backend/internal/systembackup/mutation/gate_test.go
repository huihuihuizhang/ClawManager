package mutation

import (
	"clawreef/internal/backupgate"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultRegistryRetainsTeamWorkBoundary(t *testing.T) {
	Configure(nil)
	var closed, released atomic.Bool
	var active atomic.Int64
	closed.Store(true)
	restore := backupgate.ConfigureWorkBoundary(func(context.Context) (func(), error) {
		if closed.Load() {
			return nil, backupgate.ErrMaintenance
		}
		active.Add(1)
		return func() { released.Store(true); active.Add(-1) }, nil
	})
	defer restore()
	if _, err := Enter(context.Background(), "skill-backfill"); !errors.Is(err, backupgate.ErrMaintenance) {
		t.Fatal("missing v2 registry bypassed the Team gate", err)
	}
	closed.Store(false)
	release, err := Enter(context.Background(), "skill-materialize")
	if err != nil || active.Load() != 1 || released.Load() {
		t.Fatal("work was not held", err)
	}
	if err = release(); err != nil || active.Load() != 0 || !released.Load() {
		t.Fatal("work was not released", err)
	}
	if err = release(); err != nil || active.Load() != 0 {
		t.Fatal("duplicate release changed ownership", err)
	}
}

type fakeGate struct {
	closed atomic.Bool
	active atomic.Int64
}

type invalidContextGate struct{ released atomic.Bool }

func (g *invalidContextGate) Enter(context.Context, string) (func() error, error) {
	return nil, errors.New("wrong entry")
}
func (g *invalidContextGate) EnterContext(context.Context, string) (context.Context, func() error, error) {
	return nil, func() error { g.released.Store(true); return nil }, nil
}
func TestContextAdmissionRejectsInvalidCapabilityWithoutLeakingPermit(t *testing.T) {
	g := &invalidContextGate{}
	Configure(g)
	defer Configure(nil)
	if _, release, err := EnterContext(context.Background(), "team-event"); err == nil || release != nil || !g.released.Load() {
		t.Fatal("invalid context admission leaked a permit", err)
	}
}

func (g *fakeGate) Enter(context.Context, string) (func() error, error) {
	if g.closed.Load() {
		return nil, errors.New("closed")
	}
	g.active.Add(1)
	return func() error { g.active.Add(-1); return nil }, nil
}
func TestDetachedWorkWaitsForReopenAndReleasesAfterWork(t *testing.T) {
	g := &fakeGate{}
	g.closed.Store(true)
	Configure(g)
	defer Configure(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, e := Wait(ctx, "detached")
		if e != nil {
			done <- e
			return
		}
		if g.active.Load() != 1 {
			done <- errors.New("not registered")
			return
		}
		done <- release()
	}()
	select {
	case <-done:
		t.Fatal("work crossed closed gate")
	case <-time.After(20 * time.Millisecond):
	}
	g.closed.Store(false)
	if e := <-done; e != nil || g.active.Load() != 0 {
		t.Fatal(e)
	}
}
func TestDetachedWorkHonorsCancellation(t *testing.T) {
	g := &fakeGate{}
	g.closed.Store(true)
	Configure(g)
	defer Configure(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Wait(ctx, "detached"); e == nil || g.active.Load() != 0 {
		t.Fatal("canceled work admitted")
	}
}
