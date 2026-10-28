package systembackupcontroller

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
)

// LeasedExecutionRunner renews only the active call, and joins the heartbeat
// before Record releases the claim. It cannot race Record with a late renewal.
type LeasedExecutionRunner struct {
	Runner d.Runner
	Store  *SQLExecutionWorkStore
}

func (r LeasedExecutionRunner) Prepare(ctx context.Context, in d.Input, p d.Ports) (plan d.Plan, err error) {
	if r.Store == nil || absentExecutionDependency(r.Runner) {
		return plan, d.ErrNotReady
	}
	err = r.Store.RunWithExecutionHeartbeat(ctx, in.Authority, func(ctx context.Context) error { var e error; plan, e = r.Runner.Prepare(ctx, in, p); return e })
	return
}
func (r LeasedExecutionRunner) Capture(ctx context.Context, in d.Input, plan d.Plan, p d.Ports) (results []d.ModuleResult, err error) {
	if r.Store == nil || absentExecutionDependency(r.Runner) {
		return nil, d.ErrNotReady
	}
	err = r.Store.RunWithExecutionHeartbeat(ctx, in.Authority, func(ctx context.Context) error {
		var e error
		results, e = r.Runner.Capture(ctx, in, plan, p)
		return e
	})
	return
}
func (r LeasedExecutionRunner) Recover(ctx context.Context, in d.Input, plan d.Plan, p d.Ports) (result d.RecoveryResult, err error) {
	if r.Store == nil || absentExecutionDependency(r.Runner) {
		return result, d.ErrNotReady
	}
	err = r.Store.RunWithExecutionHeartbeat(ctx, in.Authority, func(ctx context.Context) error { var e error; result, e = r.Runner.Recover(ctx, in, plan, p); return e })
	return
}

var _ d.Runner = LeasedExecutionRunner{}
