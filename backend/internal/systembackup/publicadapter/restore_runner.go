package publicadapter

import (
	"context"

	d "clawreef/internal/systembackupdispatch"
)

// NewRestoreRunner installs the real public refusal boundary. It cannot accept
// a caller proof callback, legacy bundle, version map or receipt as a full
// authenticated source. Until A exposes its complete concrete source handle,
// no target capability is available through this runner.
func NewRestoreRunner() d.RestoreRunner { return restoreRunner{} }

// The metadata envelope pins this independently supplied owner version. No
// target-plan decoder or write eligibility is claimed by the refusal runner.
const RestorePlanVersion = "system-backup-b-restore-plan.v1"

type restoreRunner struct{}

func (restoreRunner) Restore(ctx context.Context, in d.Input, spec d.DrillSpec, plan d.Plan, ports d.RestorePorts) (d.RestoreResult, error) {
	return refuseIncompleteRestore(ctx, in, spec, plan, ports, "restore")
}

func (restoreRunner) Verify(ctx context.Context, in d.Input, spec d.DrillSpec, plan d.Plan, ports d.RestorePorts) (d.RestoreResult, error) {
	return refuseIncompleteRestore(ctx, in, spec, plan, ports, "verify")
}

func refuseIncompleteRestore(ctx context.Context, in d.Input, spec d.DrillSpec, plan d.Plan, ports d.RestorePorts, phase string) (d.RestoreResult, error) {
	if nilValue(ctx) || ctx.Err() != nil || nilValue(ports) || in.Authority.Phase != phase {
		return d.RestoreResult{}, d.ErrNotReady
	}
	inner, err := d.UnwrapRestoreTaskPlan(in, spec, plan, RestorePlanVersion)
	if err != nil {
		return d.RestoreResult{}, err
	}
	clear(inner.CanonicalJSON)
	return d.RestoreResult{}, d.ErrRestoreSourceUnavailable
}
