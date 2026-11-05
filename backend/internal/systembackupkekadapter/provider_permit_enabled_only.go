package systembackupkekadapter

import (
	"context"
	"os"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
)

// Same trusted fixed original locator as D's production Forward consumer.
const permitOriginalForwardFileEnvironment = "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE"
const permitOriginalForwardSHAEnvironment = "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256"

func (i *ProviderPermitIssuer) attachOriginalEnabledOnlyForward(g ProviderPermitIssuerGrant) error {
	keys, ok := i.cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	if !ok || keys == nil || keys.GrantSHA256() != i.cfg.CaptureGrantSHA256 {
		return kms.ErrPermission
	}
	current := keys.DeploymentBinding()
	if current.ConfigVersion == g.Workload.ConfigVersion && current.ConfigSHA256 == g.Workload.ConfigSHA256 {
		return nil
	}
	if g.Workload.ConfigVersion != 1 || current.ConfigVersion != 2 {
		return kms.ErrPermission
	}
	file, sha := os.Getenv(permitOriginalForwardFileEnvironment), os.Getenv(permitOriginalForwardSHAEnvironment)
	old, e := keys.OpenOriginalEnabledOnlyPredecessor(file, sha)
	if e != nil {
		return kms.ErrPermission
	}
	prior := old.DeploymentBinding()
	if prior.ConfigVersion != g.Workload.ConfigVersion || prior.ConfigSHA256 != g.Workload.ConfigSHA256 || prior.InstallationID != i.cfg.Binding.InstallationID || prior.ControllerOwner != g.Workload.ControllerOwner || prior.ServerUUID != g.Database.ServerUUID || prior.Database != g.Database.Database || prior.DatabaseAccount != g.DatabaseAccount {
		return kms.ErrPermission
	}
	i.originalForward = old
	return nil
}

type permitEnabledOnlyLineage struct {
	origin      *permitEnabledOnlyLineage
	proof       *sec.OriginalEnabledOnlyLineage
	ctx         context.Context
	view        reg.SQLReadView
	until       time.Time
	fingerprint string
}

func (*permitEnabledOnlyLineage) MarshalJSON() ([]byte, error) { return nil, kms.ErrPermission }
func (i *ProviderPermitIssuer) bindEnabledOnlyScope(ctx context.Context, view reg.SQLReadView, g ProviderPermitIssuerGrant, a d.Authority) (*permitEnabledOnlyLineage, error) {
	if i == nil || ctx == nil || ctx.Err() != nil || nilSource(view) {
		return nil, kms.ErrPermission
	}
	if a.ConfigVersion == g.Workload.ConfigVersion && a.ConfigSHA256 == g.Workload.ConfigSHA256 {
		return nil, nil
	}
	if a.InstallationID != i.cfg.Binding.InstallationID || a.ClaimOwner != g.Workload.ControllerOwner || g.Workload.ConfigVersion != 1 || a.ConfigVersion != 2 || a.ConfigSHA256 == g.Workload.ConfigSHA256 || i.originalForward == nil {
		return nil, kms.ErrPermission
	}
	keys, ok := i.cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	if !ok || keys == nil || keys.GrantSHA256() != i.cfg.CaptureGrantSHA256 {
		return nil, kms.ErrPermission
	}
	current := keys.DeploymentBinding()
	old := i.originalForward.DeploymentBinding()
	if current.ConfigVersion != a.ConfigVersion || current.ConfigSHA256 != a.ConfigSHA256 || old.ConfigVersion != g.Workload.ConfigVersion || old.ConfigSHA256 != g.Workload.ConfigSHA256 || keys.CheckOriginalEnabledOnlyPredecessorInView(ctx, view, i.originalForward) != nil {
		return nil, kms.ErrPermission
	}
	proof, e := sec.ReadOriginalEnabledOnlyLineage(ctx, view, a.InstallationID, g.Workload.ConfigSHA256, a.ConfigVersion, a.ConfigSHA256)
	if e != nil || !proof.Matches(a.InstallationID, g.Workload.ConfigSHA256, a.ConfigVersion, a.ConfigSHA256) {
		return nil, kms.ErrPermission
	}
	until, e := proof.OriginalDiagnosticUntil(ctx, view)
	if e != nil {
		return nil, kms.ErrPermission
	}
	for _, end := range []time.Time{old.ExpiresAt, current.ExpiresAt} {
		if end.Before(until) {
			until = end
		}
	}
	fingerprint, e := proof.Fingerprint()
	if e != nil {
		return nil, kms.ErrPermission
	}
	lineage := &permitEnabledOnlyLineage{proof: proof, ctx: ctx, view: view, until: until, fingerprint: fingerprint}
	lineage.origin = lineage
	if lineage.recheck(ctx, view, i, g, a) != nil {
		return nil, kms.ErrPermission
	}
	return lineage, nil
}
func (p *permitEnabledOnlyLineage) recheck(ctx context.Context, view reg.SQLReadView, i *ProviderPermitIssuer, g ProviderPermitIssuerGrant, a d.Authority) error {
	if a.ConfigVersion == g.Workload.ConfigVersion && a.ConfigSHA256 == g.Workload.ConfigSHA256 {
		if p != nil {
			return kms.ErrPermission
		}
		return nil
	}
	if p == nil || p.origin != p || p.proof == nil || ctx == nil || view == nil || !reflect.ValueOf(ctx).Comparable() || !reflect.ValueOf(view).Comparable() || ctx != p.ctx || view != p.view || ctx.Err() != nil || !time.Now().Before(p.until) || !p.proof.Matches(a.InstallationID, g.Workload.ConfigSHA256, a.ConfigVersion, a.ConfigSHA256) {
		return kms.ErrPermission
	}
	authorized, e := p.proof.AuthorizationConfigSHA256(ctx, view)
	if e != nil || authorized != g.Workload.ConfigSHA256 {
		return kms.ErrPermission
	}
	var now time.Time
	if view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(p.until) {
		return kms.ErrPermission
	}
	keys, ok := i.cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	if !ok || keys == nil || keys.GrantSHA256() != i.cfg.CaptureGrantSHA256 || keys.CheckOriginalEnabledOnlyPredecessorInView(ctx, view, i.originalForward) != nil {
		return kms.ErrPermission
	}
	return nil
}

func (p *PreparedProviderPermitIssue) bindEnabledOnlyOriginal(ctx context.Context, view reg.SQLReadView) (*permitEnabledOnlyLineage, error) {
	lineage, e := p.issuer.bindEnabledOnlyScope(ctx, view, p.grant, p.scope.Input.Authority)
	if e != nil {
		return nil, kms.ErrPermission
	}
	if lineage == nil {
		if p.enabledFingerprint != "" {
			return nil, kms.ErrPermission
		}
		return nil, nil
	}
	if p.original == nil || lineage.fingerprint != p.enabledFingerprint || lineage.until.Before(p.until) {
		return nil, kms.ErrPermission
	}
	return lineage, nil
}
