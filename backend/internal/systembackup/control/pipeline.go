package control

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"clawreef/internal/systembackup/flow"
)

// ProfileDriver handles environment discovery and builds adapters from the
// ENCRYPTED immutable plan. Discover is read-only; Bind must not rediscover or
// allocate new identities. Old revisions remain registered during recovery.
type ProfileDriver interface {
	Metadata() Profile
	Probe(context.Context) error
	Discover(context.Context, Task) (json.RawMessage, error)
	Bind(context.Context, Task, json.RawMessage) (*Execution, error)
}

// Execution contains runtime adapters, not serialized callbacks. Drivers must
// bind every resource, credential and restart reference to their frozen plan.
// Source credentials never enter task DTOs or API responses.
type Execution struct {
	Identity                 flow.Identity
	HoldUntil                time.Time
	ResumeTimeout            time.Duration
	Writers                  []flow.Writer
	Capture, Restore, Verify []flow.Collector
	PrepareResources         func(context.Context) error
	CheckSource              func(context.Context) error
	ResolveMutations         func(context.Context) error
	Preflight                func(context.Context) error
	CheckTargetStopped       func(context.Context) error
	ValidateCapture          func(context.Context, []flow.Part) error
	Publish                  func(context.Context, []flow.Part) error
	Cleanup                  func(context.Context) error
}
type Pipeline struct {
	Store   SQLStore
	Vault   Vault
	Drivers []ProfileDriver
	// When retaining historical drivers, explicitly select the revision admitted
	// for new tasks. Recovery still resolves the revision pinned in each task.
	ActiveRevisions map[string]string
}

var _ Executor = (*Pipeline)(nil)

type PublicationResolver interface {
	ResolvePublication(context.Context, Task) error
}

func (p *Pipeline) ResolvePublication(ctx context.Context, t Task) error {
	d, e := p.driver(t)
	if e != nil {
		return e
	}
	if r, ok := d.(PublicationResolver); ok {
		return r.ResolvePublication(ctx, t)
	}
	return ErrNotFound
}

func (p *Pipeline) driver(t Task) (ProfileDriver, error) {
	var found ProfileDriver
	for _, d := range p.Drivers {
		if d == nil {
			return nil, ErrInvalid
		}
		m := d.Metadata()
		if m.ID == t.Request.Profile && m.Revision == t.ProfileRevision && m.Admits(t.Request) {
			if found != nil {
				return nil, ErrConflict
			}
			for _, kind := range m.Kinds {
				if kind == t.Request.Kind {
					found = d
				}
			}
		}
	}
	if found == nil {
		return nil, ErrNotReady
	}
	return found, nil
}
func (p *Pipeline) Profiles(ctx context.Context) ([]Profile, error) {
	out := []Profile{}
	seen := map[string]bool{}
	selected := map[string]bool{}
	for _, d := range p.Drivers {
		if d == nil {
			return nil, ErrInvalid
		}
		m := d.Metadata()
		key := m.ID + "/" + m.Revision
		if !identifier.MatchString(m.ID) || !revision.MatchString(m.Revision) || seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		if active, explicit := p.ActiveRevisions[m.ID]; explicit && active != m.Revision {
			continue
		}
		if selected[m.ID] {
			return nil, ErrInvalid
		}
		selected[m.ID] = true
		m.Ready = false
		m.Reasons = []string{"profile_dependencies_unavailable"}
		if d.Probe(ctx) == nil {
			m.Ready = true
			m.Reasons = []string{}
		}
		out = append(out, m)
	}
	for id := range p.ActiveRevisions {
		if !selected[id] {
			return nil, ErrNotReady
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (p *Pipeline) bind(ctx context.Context, t Task) (*Execution, error) {
	d, e := p.driver(t)
	if e != nil {
		return nil, e
	}
	raw, e := p.Vault.Get(ctx, t, "execution-plan", "plan")
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	x, e := d.Bind(ctx, t, raw)
	if e != nil || x == nil || x.Cleanup == nil || x.PrepareResources == nil {
		return nil, ErrNotReady
	}
	if t.Request.Kind == "backup" {
		if x.Identity.Task != t.ID || x.Identity.Attempt == "" || x.Identity.Generation <= 0 || x.Identity.Phase != "capture" || x.HoldUntil.UnixMilli() > t.Deadline || x.ResumeTimeout <= 0 || x.ResumeTimeout > 10*time.Minute || len(x.Writers) == 0 || len(x.Capture) == 0 || x.CheckSource == nil || x.ValidateCapture == nil || x.Publish == nil {
			return nil, ErrInvalid
		}
	} else if x.Preflight == nil || x.CheckTargetStopped == nil || (t.Request.Kind == "drill" && (len(x.Restore) == 0 || len(x.Verify) == 0)) {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, set := range [][]flow.Collector{x.Capture, x.Restore, x.Verify} {
		for _, c := range set {
			if c == nil || !identifier.MatchString(c.ID()) || seen[c.ID()] {
				return nil, ErrInvalid
			}
			seen[c.ID()] = true
		}
	}
	return x, nil
}
func (p *Pipeline) journal(t Task, x *Execution) PauseJournal {
	ids := make([]string, 0, len(x.Writers))
	for _, w := range x.Writers {
		if w != nil {
			ids = append(ids, w.ID())
		}
	}
	return PauseJournal{Store: p.Store, Task: t, Identity: x.Identity, Writers: ids}
}
func markerNameFor(phase, id string) string {
	// Hash rather than concatenate caller-controlled names beyond DB limits.
	return Request{Kind: phase, Profile: id}.Hash()
}
func (p *Pipeline) marked(ctx context.Context, t Task, name string) (bool, error) {
	b, e := p.Vault.Get(ctx, t, name, "progress")
	defer clear(b)
	if errors.Is(e, ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if string(b) != "confirmed" {
		return false, ErrConflict
	}
	return true, nil
}
func (p *Pipeline) mark(ctx context.Context, t Task, name string) error {
	return p.Vault.Put(ctx, t, name, "progress", []byte("confirmed"))
}
func (p *Pipeline) prepare(ctx context.Context, t Task, collectors []flow.Collector) error {
	for _, c := range collectors {
		if e := p.mark(ctx, t, markerNameFor("prepared", c.ID())); e != nil {
			return e
		}
		if e := c.Prepare(ctx); e != nil {
			return e
		}
	}
	return nil
}
func (p *Pipeline) stop(ctx context.Context, t Task, collectors []flow.Collector) error {
	var result error
	for i := len(collectors) - 1; i >= 0; i-- {
		c := collectors[i]
		prepared, e := p.marked(ctx, t, markerNameFor("prepared", c.ID()))
		if e != nil {
			result = errors.Join(result, e)
			continue
		}
		if !prepared {
			continue
		}
		if e = c.Stop(ctx); e != nil {
			result = errors.Join(result, e)
		}
	}
	return result
}
func (p *Pipeline) parts(ctx context.Context, t Task, name string) ([]flow.Part, error) {
	raw, e := p.Vault.Get(ctx, t, name, "results")
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var parts []flow.Part
	if json.Unmarshal(raw, &parts) != nil || len(parts) == 0 {
		return nil, ErrConflict
	}
	return parts, nil
}
func (p *Pipeline) saveParts(ctx context.Context, t Task, name string, parts []flow.Part) error {
	raw, e := json.Marshal(parts)
	if e != nil {
		return ErrInvalid
	}
	defer clear(raw)
	return p.Vault.Put(ctx, t, name, "results", raw)
}

func (p *Pipeline) Step(ctx context.Context, t Task) error {
	if p.Store.DB == nil || p.Vault.Store.DB != p.Store.DB {
		return ErrInvalid
	}
	if t.Status == "pending" {
		stored, e := p.Vault.Get(ctx, t, "execution-plan", "plan")
		clear(stored)
		if e == nil {
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		d, e := p.driver(t)
		if e != nil {
			return e
		}
		if e = d.Probe(ctx); e != nil {
			return ErrNotReady
		}
		raw, e := d.Discover(ctx, t)
		if e != nil {
			return e
		}
		defer clear(raw)
		if len(raw) == 0 || !json.Valid(raw) {
			return ErrInvalid
		}
		return p.Vault.Put(ctx, t, "execution-plan", "plan", raw)
	}
	x, e := p.bind(ctx, t)
	if e != nil {
		return e
	}
	if t.Request.Kind == "backup" {
		return p.backup(ctx, t, x)
	}
	switch t.Status {
	case "preflighting", "running":
		return x.Preflight(ctx)
	case "provisioning":
		if e = x.Preflight(ctx); e != nil {
			return e
		}
		return x.PrepareResources(ctx)
	case "restoring":
		return p.runTarget(ctx, t, x, x.Restore, "restore-results")
	case "normalizing":
		return x.CheckTargetStopped(ctx) // normalization is inside each restore worker before completion
	case "verifying":
		return p.runTarget(ctx, t, x, x.Verify, "verify-results")
	}
	return ErrConflict
}
func (p *Pipeline) backup(ctx context.Context, t Task, x *Execution) error {
	journal := p.journal(t, x)
	switch t.Status {
	case "preparing":
		if e := x.CheckSource(ctx); e != nil {
			return e
		}
		if e := journal.Register(ctx); e != nil {
			return e
		}
		if e := x.PrepareResources(ctx); e != nil {
			return e
		}
		return p.prepare(ctx, t, x.Capture)
	case "ready_for_capture":
		return x.CheckSource(ctx)
	case "acquiring_gate":
		if e := p.Store.CloseGate(ctx, t, x.HoldUntil); e != nil {
			return e
		}
		for {
			if x.ResolveMutations != nil {
				if e := x.ResolveMutations(ctx); e != nil {
					return e
				}
			}
			tx, e := p.Store.begin(ctx)
			if e != nil {
				return e
			}
			e = p.Store.GateDrained(ctx, tx, t, false)
			tx.Rollback()
			if e == nil {
				return nil
			}
			if !errors.Is(e, ErrNotReady) {
				return e
			}
			if !waitPoll(ctx, 250*time.Millisecond) {
				return ctx.Err()
			}
		}
	case "capturing":
		if _, e := p.parts(ctx, t, "capture-results"); e == nil {
			return p.Store.OpenGate(ctx, t)
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		// Re-entering Capture after a crash can observe already stopped/resumed
		// writers as their original state. Never do that; recover the durable intents.
		started, e := p.marked(ctx, t, "capture-started")
		if e != nil {
			return e
		}
		if started {
			return ErrConflict
		}
		if e = p.mark(ctx, t, "capture-started"); e != nil {
			return e
		}
		parts, e := flow.Capture(ctx, flow.Request{Identity: x.Identity, HoldUntil: x.HoldUntil, ResumeTimeout: x.ResumeTimeout, Writers: x.Writers, Collectors: x.Capture, Journal: journal, DependenciesReady: x.CheckSource})
		if e != nil {
			return e
		}
		if e = p.saveParts(ctx, t, "capture-results", parts); e != nil {
			return e
		}
		return p.Store.OpenGate(ctx, t)
	case "validating":
		parts, e := p.parts(ctx, t, "capture-results")
		if e != nil {
			return e
		}
		return x.ValidateCapture(ctx, parts)
	case "publishing":
		parts, e := p.parts(ctx, t, "capture-results")
		if e != nil {
			return e
		}
		return x.Publish(ctx, parts)
	}
	return ErrConflict
}
func (p *Pipeline) runTarget(ctx context.Context, t Task, x *Execution, collectors []flow.Collector, resultName string) error {
	if _, e := p.parts(ctx, t, resultName); e == nil {
		return x.CheckTargetStopped(ctx)
	} else if !errors.Is(e, ErrNotFound) {
		return e
	}
	started, e := p.marked(ctx, t, resultName+"-started")
	if e != nil {
		return e
	}
	if started {
		return ErrConflict
	}
	if e = x.CheckTargetStopped(ctx); e != nil {
		return e
	}
	if e = p.mark(ctx, t, resultName+"-started"); e != nil {
		return e
	}
	if e = p.prepare(ctx, t, collectors); e != nil {
		return e
	}
	parts := []flow.Part{}
	for _, c := range collectors {
		part, e := c.Capture(ctx)
		if e != nil {
			return e
		}
		if part.ID != c.ID() || part.Checkpoint == "" || part.SealedRef == "" {
			return ErrConflict
		}
		parts = append(parts, part)
	}
	if e = p.stop(ctx, t, collectors); e != nil {
		return e
	}
	if e = x.CheckTargetStopped(ctx); e != nil {
		return e
	}
	return p.saveParts(ctx, t, resultName, parts)
}
func (p *Pipeline) Recover(ctx context.Context, t Task) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrInvalid
	}
	x, e := p.bind(ctx, t)
	if errors.Is(e, ErrNotFound) {
		return p.Store.OpenGate(ctx, t)
	}
	if e != nil {
		return e
	}
	// Stop before source recovery, including Jobs prepared in an earlier phase.
	if e = p.stop(ctx, t, append(append(append([]flow.Collector{}, x.Capture...), x.Restore...), x.Verify...)); e != nil {
		return e
	}
	if t.Request.Kind == "backup" {
		// A crash before gate acquisition has no pause intents. Avoid inventing a
		// closed gate merely to make the recovery-journal checks succeed.
		tx, e := p.Store.begin(ctx)
		if e != nil {
			return e
		}
		if p.Store.Fence(ctx, tx, t) != nil {
			tx.Rollback()
			return ErrFence
		}
		var pending int
		e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE", t.ID).Scan(&pending)
		tx.Rollback()
		if e != nil {
			return ErrNotReady
		}
		if pending > 0 {
			if e = flow.RecoverSource(ctx, x.Identity, p.journal(t, x), x.Writers); e != nil {
				return e
			}
		}
		if e = p.Store.OpenGate(ctx, t); e != nil {
			return e
		}
	} else if e = x.CheckTargetStopped(ctx); e != nil {
		return e
	}
	return x.Cleanup(ctx)
}
