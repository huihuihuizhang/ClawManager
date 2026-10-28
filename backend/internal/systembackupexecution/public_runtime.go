package systembackupexecution

import (
	"context"
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
	ports, e := c.NewExecutionJobPorts(o.Gate, o)
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
