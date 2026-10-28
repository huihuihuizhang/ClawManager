package systembackup

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineSwitchPreservesOldHistoryAndExcludesActiveCapture(t *testing.T) {
	db := fullSchemaDB(t)
	ctx := context.Background()
	g := Gate{db}
	const scope = "engine-source"
	if err := g.EnsureScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	choice, err := g.Engine(ctx, scope)
	if err != nil || choice.Engine != LegacyEngine || choice.Version != 1 {
		t.Fatal(choice, err)
	}
	active, err := g.Begin(ctx, scope, "old-owner", RegistryHash(), time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.SwitchEngine(ctx, scope, choice, VersionedEngine); err == nil {
		t.Fatal("switched with an old source writer")
	}
	if err = g.BeginRelease(ctx, active); err != nil {
		t.Fatal(err)
	}
	if err = g.FinishRelease(ctx, active); err != nil {
		t.Fatal(err)
	}

	s := Store{db, "installation_test"}
	if err = s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveConfig(ctx, 0, 1, testConfig(), permitConfig); err != nil {
		t.Fatal(err)
	}
	request := CreateTaskRequest{Type: Backup, Purpose: "functional_test"}
	old, _, err := s.Create(ctx, 1, "engine-old-history-0001", request, permitTask)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.SwitchEngine(ctx, scope, choice, VersionedEngine); err == nil {
		t.Fatal("switched with queued old work")
	}
	if _, err = db.Exec("UPDATE system_backup_tasks SET status='canceled',can_cancel=0,finished_at=UTC_TIMESTAMP(6) WHERE public_id=?", old.ID); err != nil {
		t.Fatal(err)
	}
	// A task's terminal label cannot prove a lost external write never reached
	// the provider. Resolve its original operation before allowing a new engine.
	if _, err = db.Exec(`INSERT INTO system_backup_external_actions(public_id,task_id,action_type,state,request_hash,request_json,dispatch_deadline)
VALUES('sfa_engine_unknown',?,'manifest_put','request_sent',?,'{}',UTC_TIMESTAMP(6))`, old.ID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = g.SwitchEngine(ctx, scope, choice, VersionedEngine); err == nil {
		t.Fatal("switched while a terminal task still has an unknown provider write")
	}
	if _, err = db.Exec("UPDATE system_backup_external_actions SET state='confirmed_absent' WHERE public_id='sfa_engine_unknown'"); err != nil {
		t.Fatal(err)
	}
	selected, err := g.SwitchEngine(ctx, scope, choice, VersionedEngine)
	if err != nil || selected.Version != 2 {
		t.Fatal(selected, err)
	}
	if _, err = g.Begin(ctx, scope, "stale-old-owner", RegistryHash(), time.Minute, time.Minute); !errors.Is(err, ErrEngineConflict) {
		t.Fatal("old engine admitted", err)
	}
	if _, _, err = s.Create(ctx, 1, "engine-new-legacy-0002", request, permitTask); !errors.Is(err, ErrEngineConflict) {
		t.Fatal("old engine enqueued new work", err)
	}
	replayed, wasReplay, err := s.Create(ctx, 1, "engine-old-history-0001", request, permitTask)
	if err != nil || !wasReplay || replayed.ID != old.ID || replayed.Status != "canceled" {
		t.Fatal("lost idempotent old history", replayed, wasReplay, err)
	}
	if _, err = g.SwitchEngine(ctx, scope, choice, LegacyEngine); err == nil {
		t.Fatal("accepted stale selector version")
	}
	newOwner, err := g.BeginForEngine(ctx, VersionedEngine, scope, "v2-owner", RegistryHash(), time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.SwitchEngine(ctx, scope, selected, LegacyEngine); err == nil {
		t.Fatal("rolled back during capture")
	}
	if err = g.BeginRelease(ctx, newOwner); err != nil {
		t.Fatal(err)
	}
	if err = g.FinishRelease(ctx, newOwner); err != nil {
		t.Fatal(err)
	}
	if _, err = g.SwitchEngine(ctx, scope, selected, LegacyEngine); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, old.ID); err != nil {
		t.Fatal("rollback lost original data", err)
	}
}

func TestConcurrentEnginesShareOneCaptureGate(t *testing.T) {
	db := fullSchemaDB(t)
	ctx := context.Background()
	g := Gate{db}
	if err := g.EnsureScope(ctx, "capture-shared"); err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for _, owner := range []string{"owner-a", "owner-b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			if _, err := g.BeginForEngine(ctx, LegacyEngine, "capture-shared", owner, RegistryHash(), time.Minute, time.Minute); err == nil {
				admitted.Add(1)
			}
		}(owner)
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("capture admissions=%d", admitted.Load())
	}
}
