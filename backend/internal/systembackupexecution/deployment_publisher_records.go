package systembackupexecution

import (
	"context"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
)

// Static original record custody binding only. It does not authorize capture,
// worker issuance, provider use or a claim; the concrete publisher guard does
// all current SQL/workload checks in the separate readonly Records entry.
func (p deploymentAuthorization) CheckPublisherCaptureCustody(ctx context.Context, d s.PublisherCaptureDeployment) error {
	service := p.Service
	if service == nil || ctx == nil || ctx.Err() != nil || service.Forward == nil || service.ConfigDigest != d.DeploymentConfigSHA256 || service.Config.InstallationID != d.InstallationID || service.Config.ControllerOwner != d.ControllerOwner {
		return c.ErrExecutionAuthority
	}
	if _, err := pinnedDeploymentFile(service.ConfigPath, service.ConfigDigest, 256<<10); err != nil {
		return c.ErrExecutionAuthority
	}
	g := service.Forward.DeploymentBinding()
	if service.Forward.GrantSHA256() != d.CaptureGrantSHA256 || g.DeploymentConfigSHA256 != d.DeploymentConfigSHA256 || g.InstallationID != d.InstallationID || g.ControllerOwner != d.ControllerOwner || g.ConfigVersion != d.ConfigVersion || g.ConfigSHA256 != d.ConfigSHA256 || g.ProfileSHA256 != d.ProfileSHA256 || g.Database != d.Database || g.ServerUUID != d.ServerUUID || g.DatabaseAccount != d.DatabaseAccount || !g.NotBefore.Equal(d.NotBefore) || !g.ExpiresAt.Equal(d.Until) {
		return c.ErrExecutionAuthority
	}
	return nil
}

var _ c.PublisherCaptureCustodyBinding = deploymentAuthorization{}
