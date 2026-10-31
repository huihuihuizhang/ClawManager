package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	"context"
)

func (p deploymentAuthorization) CheckPublisherVerifierDeployment(ctx context.Context, deployment s.PublisherCaptureDeployment) error {
	if p.Service == nil || !p.Service.ForwardEnabled {
		return c.ErrExecutionAuthority
	}
	if p.Service.checkPublisherVerifierBinding(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	return p.CheckPublisherCaptureCustody(ctx, deployment)
}

var _ c.PublisherVerifierDeploymentBinding = deploymentAuthorization{}
