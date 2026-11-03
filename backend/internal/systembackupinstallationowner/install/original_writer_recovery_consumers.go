package install

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
)

// This is used only by shared READ helpers on the exact original actor. It
// never changes owner.check and cannot authorize stop/acquire/copy/adoption.
func originalMaintenanceReadCheck(ctx context.Context, owner *OriginalWriterMaintenance, recovery *originalWriterRecoveryFence) error {
	if owner == nil {
		return ErrInstall
	}
	if recovery == nil {
		return owner.check(ctx)
	}
	if recovery.owner != owner {
		return ErrInstall
	}
	return recovery.checkReleasing(ctx)
}
func (f *originalWriterRecoveryFence) checkReleasing(ctx context.Context) error {
	if f == nil || f.owner == nil || f.owner.token.State != c.GateReleasing {
		return ErrInstall
	}
	return f.check(ctx)
}
