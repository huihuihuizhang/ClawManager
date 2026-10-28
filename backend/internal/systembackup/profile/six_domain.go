package profile

import (
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/recovery"
)

// SixDomainOwner supplies real frozen checkpoints for the other domains, not
// inferred empty parts. Its implementations belong to versioned owner adapters.
// Contribute may read already captured immutable objects; it must not recapture
// live data after the source pause window has ended.
type SixDomainOwner interface {
	Probe(context.Context, recovery.Reference) error
	Discover(context.Context, control.Task) (json.RawMessage, error)
	// Bind is pure: reconstruct adapters from frozen discovery, without I/O.
	Bind(control.Task, json.RawMessage) (*SixDomainExecution, error)
	Contribute(context.Context, control.Task, artifact.Bundle, []flow.Part) (control.SixDomainPlan, error)
	Publisher(context.Context, control.Task) (recovery.Publisher, error)
}

// Optional explicit capability; functional owners cannot opt in implicitly.
type SixDomainAcceptanceOwner interface {
	control.AcceptanceVerifier
	ProbeAcceptance(context.Context, recovery.Reference) error
}

type SixDomainExecution struct {
	Writers                                         []flow.Writer
	Collectors                                      []flow.Collector
	Prepare, CheckSource, ResolveMutations, Cleanup func(context.Context) error
	Validate                                        func(context.Context, []flow.Part) error
}

func (d *Driver) bindSix(t control.Task, p plan) (*SixDomainExecution, error) {
	if d.Config.SixDomainModule == nil {
		if len(p.OwnerPlan) != 0 {
			return nil, ErrProfile
		}
		return nil, nil
	}
	if d.SixDomain == nil || t.Request.Kind != "backup" || len(p.OwnerPlan) == 0 || len(p.OwnerPlan) > 4<<20 || !json.Valid(p.OwnerPlan) {
		return nil, ErrProfile
	}
	x, e := d.SixDomain.Bind(t, append(json.RawMessage(nil), p.OwnerPlan...))
	if e != nil || x == nil || len(x.Collectors) == 0 || x.Prepare == nil || x.CheckSource == nil || x.ResolveMutations == nil || x.Cleanup == nil || x.Validate == nil {
		return nil, ErrProfile
	}
	seen := map[string]bool{}
	for _, w := range p.Work {
		seen[w.ID] = true
	}
	for _, c := range x.Collectors {
		if c == nil || c.ID() == "" || seen[c.ID()] {
			return nil, ErrProfile
		}
		seen[c.ID()] = true
	}
	return x, nil
}

func ownParts(p plan, parts []flow.Part) []flow.Part {
	ids := map[string]bool{}
	for _, w := range p.Work {
		ids[w.ID] = true
	}
	out := []flow.Part{}
	for _, part := range parts {
		if ids[part.ID] {
			out = append(out, part)
		}
	}
	return out
}

func (d *Driver) prepareSixDomain(ctx context.Context, t control.Task, b artifact.Bundle, parts []flow.Part) error {
	if d.SixDomain == nil || d.Config.SixDomainModule == nil {
		return ErrProfile
	}
	// Frozen plans are never regenerated on retries or a controller takeover.
	if raw, e := d.Vault.Get(ctx, t, "six-domain-publication", "plan"); e == nil {
		defer clear(raw)
		var p control.SixDomainPlan
		if json.Unmarshal(raw, &p) != nil {
			return ErrProfile
		}
		return d.authorizeAcceptance(ctx, t, p)
	} else if e != control.ErrNotFound {
		return e
	}
	p, e := d.SixDomain.Contribute(ctx, t, b, parts)
	if e != nil {
		return e
	}
	if e = control.FreezeSixDomainPlan(ctx, d.Vault, t, p); e != nil {
		return e
	}
	return d.authorizeAcceptance(ctx, t, p)
}
func (d *Driver) authorizeAcceptance(ctx context.Context, t control.Task, p control.SixDomainPlan) error {
	if t.Request.Purpose != "acceptance" {
		return nil
	}
	if !d.Metadata().Admits(t.Request) {
		return ErrProfile
	}
	a, ok := d.SixDomain.(SixDomainAcceptanceOwner)
	if !ok {
		return ErrProfile
	}
	return control.AuthorizeSixDomainAcceptance(ctx, d.Vault, t, p, a)
}
func (d *Driver) publishSixDomain(ctx context.Context, t control.Task, readOnly bool) error {
	if d.SixDomain == nil {
		return ErrProfile
	}
	p, e := d.SixDomain.Publisher(ctx, t)
	if e != nil {
		return e
	}
	if p.Artifact.Store == nil || p.Catalog.Store == nil {
		return ErrProfile
	}
	if readOnly {
		p.Artifact.Store = readOnlyAppend{p.Artifact.Store}
		p.Catalog.Store = readOnlyAppend{p.Catalog.Store}
	}
	a, _ := d.SixDomain.(SixDomainAcceptanceOwner)
	return (control.SixDomainPublisher{Store: d.Store, Vault: d.Vault, Publisher: p, AcceptanceVerifier: a}).Publish(ctx, t)
}

type readOnlyAppend struct{ recovery.AppendProvider }

func (readOnlyAppend) Create(context.Context, recovery.Request) (recovery.Observation, error) {
	return recovery.Observation{}, recovery.ErrUnavailable
}
func (d *Driver) ResolvePublication(ctx context.Context, t control.Task) error {
	if d.Config.SixDomainModule == nil {
		return control.ErrNotFound
	}
	return d.publishSixDomain(ctx, t, true)
}
