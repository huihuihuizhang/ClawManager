package control

import (
	"clawreef/internal/systembackup/recovery"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

type catalogMemoryRecords map[string][]byte

func (m catalogMemoryRecords) Get(_ context.Context, _ Task, n, _ string) ([]byte, error) {
	b, ok := m[n]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}
func (m catalogMemoryRecords) Put(_ context.Context, _ Task, n, _ string, b []byte) error {
	if old, ok := m[n]; ok && string(old) != string(b) {
		return ErrConflict
	}
	m[n] = append([]byte(nil), b...)
	return nil
}

type emptyDiscovery struct{ calls int }

func (d *emptyDiscovery) Open(context.Context, recovery.Object) (io.ReadCloser, error) {
	return nil, ErrNotReady
}
func (d *emptyDiscovery) Observe(context.Context, string) (recovery.Observation, error) {
	return recovery.Observation{}, ErrNotReady
}
func (d *emptyDiscovery) Begin(_ context.Context, deadline int64) (recovery.Snapshot, error) {
	d.calls++
	return recovery.Snapshot{ID: "empty", Mode: "inventory_manifest", Root: recovery.Reference{ID: "catalog", Version: "v1", SHA256: strings.Repeat("a", 64)}, RecordsSHA256: recovery.Hash([]byte("clawmanager/catalog-inventory/v1")), ExpiresAt: deadline + 1000}, nil
}
func (d *emptyDiscovery) Page(_ context.Context, s recovery.Snapshot, cursor string, page int64) (recovery.Page, error) {
	return recovery.Page{SnapshotID: s.ID, Number: page, Cursor: cursor, Objects: []recovery.Object{}}, nil
}

type emptyScanJournal struct {
	state recovery.ScanState
	pages []recovery.ScanPage
}

func (j *emptyScanJournal) Load(context.Context, string) (recovery.ScanState, error) {
	return j.state, nil
}
func (j *emptyScanJournal) Start(_ context.Context, _ string, s recovery.Snapshot) (recovery.ScanState, error) {
	j.state = recovery.ScanState{Snapshot: s}
	return j.state, nil
}
func (j *emptyScanJournal) CommitPage(_ context.Context, _ string, old, next recovery.ScanState, p recovery.ScanPage, _ []recovery.ScannedRecord) error {
	if old != j.state {
		return ErrConflict
	}
	j.state = next
	j.pages = append(j.pages, p)
	return nil
}
func (j *emptyScanJournal) Finish(_ context.Context, _ string, s recovery.ScanState) error {
	if recovery.ValidateInventory(s, nil, nil) != nil || recovery.ValidatePages(s, j.pages, nil) != nil {
		return ErrConflict
	}
	j.state.Complete = true
	return nil
}
func TestCatalogScanRunsThroughControllerWithoutSourceOrTarget(t *testing.T) {
	task := testTask()
	task.Request.Kind = "catalog_scan"
	task.ProfileRevision = strings.Repeat("a", 64)
	store := &memoryTasks{task: task}
	records := catalogMemoryRecords{}
	source := &emptyDiscovery{}
	journal := &emptyScanJournal{}
	b := CatalogBinding{Profile: Profile{ID: task.Request.Profile, Revision: task.ProfileRevision, Kinds: []string{"catalog_scan"}}, Identity: recovery.Reference{ID: "catalog", Version: "v1", SHA256: strings.Repeat("a", 64)}, Discovery: source, Probe: func(context.Context, bool) error { return nil }}
	executor := &CatalogExecutor{Bindings: []CatalogBinding{b}, Records: records, Scans: func(Task, recovery.Trust) recovery.ScanJournal { return journal }, Fence: func(_ context.Context, t Task) error {
		current, _ := store.Get(context.Background(), t.ID)
		if current.Owner != t.Owner || current.Generation != t.Generation || current.Status != t.Status {
			return ErrFence
		}
		return nil
	}, Now: func() int64 { return time.Now().UnixMilli() }}
	c := Controller{Store: store, Executor: executor, Owner: "controller", Lease: 3 * time.Second, RecoveryTimeout: time.Second}
	if e := c.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := store.Get(context.Background(), task.ID)
	if got.Status != "succeeded" || source.calls != 1 || len(records["catalog-result"]) == 0 || !journal.state.Complete {
		t.Fatal("scan not persisted", got)
	}
}
func TestCatalogExecutorRefusesChangedFrozenProviderAndIncompleteImport(t *testing.T) {
	task := testTask()
	task.Request.Kind = "catalog_scan"
	task.ProfileRevision = strings.Repeat("a", 64)
	b := CatalogBinding{Profile: Profile{ID: task.Request.Profile, Revision: task.ProfileRevision, Kinds: []string{"catalog_scan", "catalog_import"}}, Identity: recovery.Reference{ID: "catalog", Version: "v1", SHA256: strings.Repeat("a", 64)}, Probe: func(context.Context, bool) error { return nil }}
	records := catalogMemoryRecords{}
	e := &CatalogExecutor{Bindings: []CatalogBinding{b}, Records: records, Fence: func(context.Context, Task) error { return nil }, Now: func() int64 { return time.Now().UnixMilli() }}
	if err := e.Step(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	task.Status = "running"
	e.Bindings[0].Identity.ID = "other"
	if err := e.Step(context.Background(), task); err == nil || len(records["catalog-result"]) != 0 {
		t.Fatal("changed provider accepted", err)
	}
	task.Request.Kind = "catalog_import"
	task.Request.Artifact = "sbr_" + strings.Repeat("a", 32)
	task.Request.RecordSHA256 = strings.Repeat("a", 64)
	task.Status = "pending"
	e.Records = catalogMemoryRecords{}
	if err := e.Step(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	task.Status = "running"
	if err := e.Step(context.Background(), task); err == nil {
		t.Fatal("missing bootstrap/provider reported success")
	}
}
func TestCatalogRequestPinsHashAndKeepsAcceptanceDisabled(t *testing.T) {
	r := Request{Kind: "catalog_import", Profile: "catalog", Artifact: "sbr_" + strings.Repeat("a", 32), RecordSHA256: strings.Repeat("a", 64), Purpose: "functional_test"}
	if r.Validate() != nil {
		t.Fatal("valid import rejected")
	}
	r.RecordSHA256 = ""
	if r.Validate() == nil {
		t.Fatal("unpinned import")
	}
	r = Request{Kind: "catalog_scan", Profile: "catalog", Purpose: "acceptance"}
	if r.Validate() == nil {
		t.Fatal("acceptance enabled")
	}
	r.Purpose = "functional_test"
	if r.Validate() != nil {
		t.Fatal("scan rejected")
	}
	r.Artifact = "unexpected"
	if r.Validate() == nil {
		t.Fatal("scan accepted unused artifact")
	}
}
