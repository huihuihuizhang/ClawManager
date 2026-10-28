package control

import (
	"context"
	"errors"
	"sort"
	"time"

	"clawreef/internal/systembackup/recovery"
)

type CatalogBinding struct {
	Profile   Profile
	Identity  recovery.Reference
	Discovery recovery.Discovery
	Importer  recovery.Importer
	Probe     func(context.Context, bool) error
}

// PrivateJournal allows controller tests without a real SQL database. Runtime
// wiring uses the same fenced, encrypted Vault as the task controller.
type PrivateJournal interface {
	Get(context.Context, Task, string, string) ([]byte, error)
	Put(context.Context, Task, string, string, []byte) error
}
type CatalogExecutor struct {
	Fallback Executor
	Bindings []CatalogBinding
	Records  PrivateJournal
	Scans    func(Task, recovery.Trust) recovery.ScanJournal
	Fence    func(context.Context, Task) error
	Now      func() int64
}

func catalogKind(k string) bool { return k == "catalog_scan" || k == "catalog_import" }
func (e *CatalogExecutor) binding(t Task) (CatalogBinding, error) {
	for _, b := range e.Bindings {
		if b.Profile.ID == t.Request.Profile && b.Profile.Revision == t.ProfileRevision {
			for _, k := range b.Profile.Kinds {
				if k == t.Request.Kind {
					return b, nil
				}
			}
		}
	}
	return CatalogBinding{}, ErrNotReady
}
func (e *CatalogExecutor) Profiles(ctx context.Context) ([]Profile, error) {
	out := []Profile{}
	if e.Fallback != nil {
		var err error
		out, err = e.Fallback.Profiles(ctx)
		if err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, p := range out {
		seen[p.ID] = true
	}
	for _, b := range e.Bindings {
		p := b.Profile
		if seen[p.ID] || !identifier.MatchString(p.ID) || !revision.MatchString(p.Revision) || b.Probe == nil {
			return nil, ErrInvalid
		}
		seen[p.ID] = true
		p.Ready = false
		p.Reasons = []string{"catalog_dependencies_unavailable"}
		full := false
		for _, k := range p.Kinds {
			if !catalogKind(k) {
				return nil, ErrInvalid
			}
			full = full || k == "catalog_scan"
		}
		if b.Probe(ctx, full) == nil {
			p.Ready = true
			p.Reasons = []string{}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type catalogPlan struct {
	Revision      string
	Identity      recovery.Reference
	RequestSHA256 string
}

func (e *CatalogExecutor) ResolvePublication(ctx context.Context, t Task) error {
	if r, ok := e.Fallback.(PublicationResolver); ok {
		return r.ResolvePublication(ctx, t)
	}
	return ErrNotFound
}

func (e *CatalogExecutor) Step(ctx context.Context, t Task) error {
	if !catalogKind(t.Request.Kind) {
		if e.Fallback == nil {
			return ErrNotReady
		}
		return e.Fallback.Step(ctx, t)
	}
	if t.Request.Validate() != nil || e.Records == nil || e.Fence == nil || e.Now == nil || e.Fence(ctx, t) != nil {
		return ErrFence
	}
	b, err := e.binding(t)
	if err != nil {
		return err
	}
	want, _ := recovery.Marshal(catalogPlan{t.ProfileRevision, b.Identity, t.Request.Hash()})
	frozen, err := e.Records.Get(ctx, t, "catalog-plan", "plan")
	defer clear(frozen)
	if t.Status == "pending" {
		if err == nil {
			if string(frozen) != string(want) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if b.Probe == nil || b.Probe(ctx, t.Request.Kind == "catalog_scan") != nil {
			return ErrNotReady
		}
		return e.Records.Put(ctx, t, "catalog-plan", "plan", want)
	}
	if t.Status != "running" || err != nil || string(frozen) != string(want) {
		return ErrConflict
	}
	if e.Now() >= t.Deadline {
		return ErrFence
	}
	var result []byte
	if t.Request.Kind == "catalog_scan" {
		if e.Scans == nil || b.Discovery == nil {
			return ErrNotReady
		}
		scanner := recovery.Scanner{Source: b.Discovery, Trust: b.Importer.Catalog.Trust, Journal: e.Scans(t, b.Importer.Catalog.Trust), Now: e.Now}
		for {
			if ctx.Err() != nil || e.Fence(ctx, t) != nil {
				return ErrFence
			}
			done, err := scanner.Step(ctx, t.ID, t.Deadline)
			if err != nil {
				return err
			}
			if done {
				break
			}
		}
		state, err := scanner.Journal.Load(ctx, t.ID)
		if err != nil || !state.Complete {
			return ErrNotReady
		}
		result, err = recovery.Marshal(state)
		if err != nil {
			return ErrInvalid
		}
	} else {
		imported, err := b.Importer.Import(ctx, t.Request.Artifact, t.Request.RecordSHA256)
		if err != nil {
			return err
		}
		// Verification is repeated on retries; the immutable result does not
		// depend on retry wall time and is not a perpetual restore authorization.
		result, err = recovery.Marshal(struct {
			RecordID, SHA256 string
			Manifest         recovery.Manifest
		}{imported.RecordID, imported.SHA256, imported.Manifest})
		if err != nil {
			return ErrInvalid
		}
	}
	if e.Fence(ctx, t) != nil {
		return ErrFence
	}
	return e.Records.Put(ctx, t, "catalog-result", "results", result)
}
func (e *CatalogExecutor) Recover(ctx context.Context, t Task) error {
	if !catalogKind(t.Request.Kind) {
		if e.Fallback == nil {
			return ErrNotReady
		}
		return e.Fallback.Recover(ctx, t)
	}
	if e.Fence == nil {
		return ErrNotReady
	}
	return e.Fence(ctx, t) // no remote mutations to undo
}
func NewCatalogExecutor(store SQLStore, v Vault, fallback Executor, bindings []CatalogBinding) *CatalogExecutor {
	return &CatalogExecutor{Fallback: fallback, Bindings: bindings, Records: v, Scans: func(t Task, trust recovery.Trust) recovery.ScanJournal {
		return CatalogScans{Store: store, Task: t, Trust: trust}
	}, Fence: func(ctx context.Context, t Task) error {
		tx, e := store.begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if store.Fence(ctx, tx, t) != nil {
			return ErrFence
		}
		current, e := load(ctx, tx, t.ID)
		if e != nil || current.Status != t.Status {
			return ErrFence
		}
		return nil
	}, Now: func() int64 { return time.Now().UnixMilli() }}
}
