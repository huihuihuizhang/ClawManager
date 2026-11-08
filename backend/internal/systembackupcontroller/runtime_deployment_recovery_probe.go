package systembackupcontroller

import (
	"context"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// Call only inside transaction after readRuntimeControl for the same authority.
// A configured probe's failure is final; recovery cannot replace that decision.
func (o *SQLRuntimeControl) checkJournaledDeployment(ctx context.Context, a d.Authority, spec b.RuntimeWriterSpec, recovery bool) error {
	if probe := o.cfg.DeploymentChecks[spec.Source.Namespace+"/"+spec.Name]; !absentExecutionDependency(probe) {
		return probe.Check(ctx)
	}
	if !recovery || o.cfg.RecoveryDeploymentCheck == nil || a.TaskPublicID == "" || a.AttemptNo == 0 ||
		spec.Kind != "deployment" || spec.Name == "" || spec.UID == "" || spec.Source.Namespace == "" || spec.Source.Namespace == o.cfg.Namespace ||
		spec.Source.ID <= 0 || spec.Source.UserID <= 0 || spec.Source.Generation <= 0 || spec.Source.Mode != "pro" || spec.Source.OS != "linux" || spec.Source.Status != "running" ||
		spec.RestartRef != a.TaskPublicID+"/"+strconv.FormatUint(a.AttemptNo, 10)+"/"+strconv.Itoa(spec.Source.ID) {
		return ErrExecutionRecord
	}
	return o.cfg.RecoveryDeploymentCheck(ctx, a, spec)
}
