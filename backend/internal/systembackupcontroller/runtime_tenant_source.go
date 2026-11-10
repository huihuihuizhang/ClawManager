package systembackupcontroller

import (
	"context"

	b "clawreef/internal/systembackup/publicadapter"
)

func (o *SQLRuntimeControl) checkSourceLocation(ctx context.Context, source b.InstanceIdentity) error {
	if source.Namespace == "" || source.Namespace == o.cfg.Namespace {
		return nil
	}
	if source.ID <= 0 || source.UserID <= 0 || !source.ValidRuntimeGeneration() || source.Mode != "pro" || source.OS != "linux" ||
		source.Status != "running" || source.Pod == "" || o.cfg.TenantProSourceCheck == nil {
		return ErrExecutionRecord
	}
	if err := o.cfg.TenantProSourceCheck(ctx, source); err != nil {
		return ErrExecutionRecord
	}
	return ctx.Err()
}
