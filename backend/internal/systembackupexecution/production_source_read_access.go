package systembackupexecution

import (
	"context"

	d "clawreef/internal/systembackupdispatch"
)

// Closed metadata authority: no exported implementation, callback or passed
// flag. Capture retains its real task; observation has its own original scope.
type sourceMetadataReadAuthority interface {
	Recheck(context.Context) error
	sourceMetadataReadAuthority()
}

func (*originalSourceMetadataAuthority) sourceMetadataReadAuthority() {}
func (sourceMetadataReadAccess) sourceMetadataReadAuthority()         {}

type sourceMetadataReadAccess struct {
	capture     *originalSourceMetadataAuthority
	observation *sourceSQLObservation
	service     *DeploymentService
	owner       *PublicJobOwner
}

func captureMetadataReadAccess(x *originalSourceMetadataAuthority) sourceMetadataReadAccess {
	if x == nil {
		return sourceMetadataReadAccess{}
	}
	return sourceMetadataReadAccess{capture: x, service: x.service, owner: x.owner}
}

func (x *sourceSQLObservation) metadataReadAccess() sourceMetadataReadAccess {
	if x == nil || x.delegation == nil {
		return sourceMetadataReadAccess{}
	}
	return sourceMetadataReadAccess{observation: x, service: x.delegation.service, owner: x.delegation.owner}
}

func (x sourceMetadataReadAccess) Recheck(ctx context.Context) error {
	if x.service == nil || x.owner == nil {
		return d.ErrNotReady
	}
	if x.capture != nil && x.observation == nil && x.capture.service == x.service && x.capture.owner == x.owner {
		return x.capture.Recheck(ctx)
	}
	if x.observation != nil && x.capture == nil && x.observation.delegation != nil && x.observation.delegation.service == x.service && x.observation.delegation.owner == x.owner {
		return x.observation.recheck(ctx)
	}
	return d.ErrNotReady
}
