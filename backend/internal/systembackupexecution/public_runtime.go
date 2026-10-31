package systembackupexecution

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

type PublicCaptureConfig struct {
	Owner   *PublicJobOwner
	Queue   c.SQLExecutionQueue
	Source  b.LinuxProfileConfig
	Profile b.ProfileKey
	// These are the existing admitted registry/owner checks, not model inputs.
	Admission         func(context.Context, d.Input) error
	RecoveryAdmission func(context.Context, d.Input) error
	Inventory         func(context.Context, d.Input, b.Discovery) error
	Guard             c.ReadinessProbe
	RecoveryTimeout   time.Duration
	// Optional D SQL runtime control. It supplies the concrete B writer factory.
	RuntimeControl *c.SQLRuntimeControl
	// Runtime opt-in must retain C's concrete platform writers and original IDs.
	// Missing this explicit group fails rather than overwriting the old hook.
	PlatformWriters *b.PlatformWriterGroup
	// Optional B module intake. Nil preserves the current workspace-only factory;
	// this does not widen supportedPublicCapture, admission, or readiness.
	Modules *b.CaptureModules
	// Original task-scoped modules are assembled after the SAME Discover's
	// writer snapshot. A callback may not rediscover writer state or issue keys.
	ModuleFactory func(d.Input, b.SourceInventory, time.Time, []b.FrozenWriter) (*b.CaptureModules, error)
	FormalKeys    FormalCandidateKeyFactory
}
type PublicCapture struct {
	Loop      c.TaskExecutionLoop
	Control   http.Handler
	Scheduler *c.SQLExecutionWorkStore
	Owner     *PublicJobOwner
}

// This composition has only a verified workspace credential/result provider.
// Reject unsupported domains during Prepare, before closing the source gate.
func supportedPublicCapture(in d.Input) error {
	if in.Backup == nil || in.Backup.TaskPurpose != "functional_test" || len(in.Backup.RequestedParts) != 1 || in.Backup.RequestedParts[0] != "workspace" {
		return d.ErrNotReady
	}
	return nil
}

type publicCaptureGuard struct {
	Outer c.ReadinessProbe
	Owner *PublicJobOwner
}

func (g publicCaptureGuard) Check(ctx context.Context) error {
	if e := g.Outer.Check(ctx); e != nil {
		return e
	}
	if e := g.Owner.Gate.Ready(ctx); e != nil {
		return e
	}
	if e := g.Owner.candidateJournalReady(ctx); e != nil {
		return e
	}
	return g.Owner.namespace(ctx)
}

// NewPublicCapture is the concrete D->B->actual Job composition. There is one
// queue, one task table and the application gate used by legacy/Team writes.
// Construction performs no source IO and does not enable HTTP submission.
func NewPublicCapture(cfg PublicCaptureConfig) (*PublicCapture, error) {
	o := cfg.Owner
	if !o.ready() || cfg.Guard == nil || cfg.Admission == nil || cfg.Inventory == nil || cfg.Profile.ID == "" || cfg.Profile.Revision == "" || cfg.Queue.DB != o.Gate.Authority.DB || cfg.Queue.ApplicationScope != o.Gate.Authority.ApplicationScope || cfg.Queue.Recovery == nil || cfg.Queue.Recovery.Identity != o.Gate.Recovery.Identity {
		return nil, d.ErrNotReady
	}
	if cfg.FormalKeys != nil {
		o.FormalKeys = cfg.FormalKeys
	}
	ports, e := c.NewExecutionJobPorts(o.Gate, o)
	if e != nil {
		return nil, e
	}
	cfg.Source, e = configuredPublicSource(cfg)
	if e != nil {
		return nil, e
	}
	profile, e := b.NewLinuxProfile(cfg.Source)
	if e != nil {
		return nil, e
	}
	admit := func(ctx context.Context, in d.Input) error {
		if e := supportedPublicCapture(in); e != nil {
			return e
		}
		return cfg.Admission(ctx, in)
	}
	recoveryAdmit := admit
	if cfg.RecoveryAdmission != nil {
		recoveryAdmit = func(ctx context.Context, in d.Input) error {
			if e := supportedPublicCapture(in); e != nil {
				return e
			}
			return cfg.RecoveryAdmission(ctx, in)
		}
	}
	runner, e := b.NewPublicRunner(b.Dependencies{Profiles: map[b.ProfileKey]b.Profile{cfg.Profile: profile}, Results: PublicResults{Owner: o}, Recovery: o, Admission: admit, RecoveryAdmission: recoveryAdmit, ValidateInventory: cfg.Inventory, RecoveryTimeout: cfg.RecoveryTimeout})
	if e != nil {
		return nil, e
	}
	bound, e := d.BindTaskRunner(runner, b.PlanVersion)
	if e != nil {
		return nil, e
	}
	scheduler := &c.SQLExecutionWorkStore{Queue: cfg.Queue, Authority: o.Gate.Authority, Records: o.Gate.Records, PrepareCapture: o.Gate.PrepareCapture, FinishCapture: o.Gate.FinishCapture}
	durable := c.DurableExecutionStore{Scheduler: scheduler, Records: o.Gate.Records}
	leased := c.LeasedExecutionRunner{Runner: bound, Store: scheduler}
	loop := c.TaskExecutionLoop{Guard: publicCaptureGuard{Outer: cfg.Guard, Owner: o}, Store: durable, Dispatch: d.Dispatcher{Runner: leased, Ports: ports}, Interval: cfg.Queue.Policy.ReconcileInterval}
	if e = loop.Validate(); e != nil {
		return nil, e
	}
	handler := WorkloadIdentity{Client: o.Client, Namespace: o.Namespace, ServiceAccount: o.Security.ServiceAccountName, ServiceAccountUID: o.Security.ServiceAccountUID, Next: worker.ControlHandler{Authorizer: o}}
	return &PublicCapture{Loop: loop, Control: handler, Scheduler: scheduler, Owner: o}, nil
}

// configuredPublicSource is also used by the production constructor above.
// Optional B modules never replace D/C's writer authority or current guards.
func configuredPublicSource(cfg PublicCaptureConfig) (b.LinuxProfileConfig, error) {
	var e error
	if cfg.Modules != nil && (cfg.ModuleFactory != nil || cfg.Source.BuildPartsWithWriters != nil) {
		return b.LinuxProfileConfig{}, d.ErrNotReady
	}
	if cfg.RuntimeControl != nil {
		if cfg.Owner == nil {
			return b.LinuxProfileConfig{}, d.ErrNotReady
		}
		if e = cfg.RuntimeControl.CheckGate(cfg.Owner.Gate); e != nil {
			return b.LinuxProfileConfig{}, e
		}
		if cfg.PlatformWriters == nil {
			return b.LinuxProfileConfig{}, d.ErrNotReady
		}
		cfg.Source.BuildWriters, e = b.ComposeRuntimeWriters(cfg.RuntimeControl.BuildWriters, *cfg.PlatformWriters)
		if e != nil {
			return b.LinuxProfileConfig{}, e
		}
	}
	if cfg.Modules != nil {
		cfg.Source, e = b.WithCaptureModules(cfg.Source, cfg.Modules)
		if e != nil {
			return b.LinuxProfileConfig{}, e
		}
	}
	if cfg.ModuleFactory != nil {
		cfg.Source.BuildPartsWithWriters = func(in d.Input, inventory b.SourceInventory, hold time.Time, writers []b.FrozenWriter) ([]b.JobPart, error) {
			if cfg.Source.RecoveryOnly {
				return nil, d.ErrNotReady
			}
			if in.Authority.TaskType == "preflight" {
				return []b.JobPart{{Part: "source_inventory", Category: "preflight"}}, nil
			}
			original := append([]b.FrozenWriter{}, writers...)
			payload, err := json.Marshal(struct {
				Input     d.Input
				Inventory b.SourceInventory
				Writers   []b.FrozenWriter
			}{in, inventory, original})
			var detached struct {
				Input     d.Input
				Inventory b.SourceInventory
				Writers   []b.FrozenWriter
			}
			if err != nil || len(payload) > 16<<20 || json.Unmarshal(payload, &detached) != nil {
				return nil, d.ErrNotReady
			}
			modules, err := cfg.ModuleFactory(detached.Input, detached.Inventory, hold, detached.Writers)
			if err != nil || modules == nil {
				return nil, d.ErrNotReady
			}
			parts, err := modules.BuildParts(in, inventory, hold)
			if err != nil {
				return nil, err
			}
			if err = validateOriginalResourceWriters(parts, original); err != nil {
				return nil, err
			}
			return parts, nil
		}
	}
	validateParts := func(in d.Input, parts []b.JobPart, err error) ([]b.JobPart, error) {
		if err != nil {
			return nil, err
		}
		if in.Authority.TaskType == "preflight" {
			return parts, nil
		}
		for _, part := range parts {
			var invocation worker.Invocation
			if json.Unmarshal(part.InvocationJSON, &invocation) != nil {
				return nil, d.ErrNotReady
			}
			if invocation.FormalCapture != nil || invocation.ProviderKey != nil {
				if !worker.ValidateRecordedInvocation(invocation) || (cfg.FormalKeys == nil && (cfg.Owner == nil || cfg.Owner.FormalKeys == nil)) {
					return nil, d.ErrNotReady
				}
			}
		}
		return parts, nil
	}
	if build := cfg.Source.BuildParts; build != nil {
		cfg.Source.BuildParts = func(in d.Input, inv b.SourceInventory, hold time.Time) ([]b.JobPart, error) {
			parts, err := build(in, inv, hold)
			return validateParts(in, parts, err)
		}
	}
	if build := cfg.Source.BuildPartsWithWriters; build != nil {
		cfg.Source.BuildPartsWithWriters = func(in d.Input, inv b.SourceInventory, hold time.Time, writers []b.FrozenWriter) ([]b.JobPart, error) {
			parts, err := build(in, inv, hold, writers)
			return validateParts(in, parts, err)
		}
	}
	return cfg.Source, nil
}

func validateOriginalResourceWriters(parts []b.JobPart, writers []b.FrozenWriter) error {
	frozen := map[string]b.FrozenWriter{}
	for _, w := range writers {
		if w.ID == "" || frozen[w.ID].ID != "" {
			return d.ErrNotReady
		}
		frozen[w.ID] = w
	}
	for _, part := range parts {
		var i worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &i) != nil {
			return d.ErrNotReady
		}
		if i.Request.Resources == nil {
			continue
		}
		for _, saved := range i.Request.Resources.OriginalWriters {
			original, ok := frozen[saved.ID]
			if !ok || original.Original != saved.State {
				return d.ErrNotReady
			}
		}
	}
	return nil
}
