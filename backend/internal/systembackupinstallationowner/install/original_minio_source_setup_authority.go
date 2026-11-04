package install

import "context"

// Narrow bridge for C's concrete native installer. The source authoring object
// grants READS only; this separate actual original maintenance owner authorizes
// the setup mutation. Both must belong to the same real Installer and original
// caller context. No enabled KEK/task/grant or caller observation is required.
func (p *OriginalWriterMaintenance) CheckOriginalMinIOSourceSetup(ctx context.Context, source *BootstrapSourceRegistryAuthoring) error {
	if p == nil || source == nil || source.origin != source || p.operator == nil || source.operator == nil || p.operator.installer != source.operator.installer || !consumerSameContext(ctx, p.ctx) || !consumerSameContext(ctx, source.ctx) || p.check(ctx) != nil || source.RecheckAuthority(ctx) != nil {
		return ErrInstall
	}
	return nil
}
