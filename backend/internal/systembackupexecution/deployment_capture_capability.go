package systembackupexecution

import d "clawreef/internal/systembackupdispatch"

// An attached plan proves only builder composition. Positive six-part state
// must come from the acknowledged runtime-readiness transaction, after actual
// taskless source/writer and ordinary provider dependency observations. Checks
// cover the complete actual writer set and its original observation window:
// a stopped observer is required only when that set contains stopped writers,
// and incomplete observations cannot establish their absence. Task admission
// and capture must independently reject later writer-set/state drift.
// Neither acceptance_ready=false nor not_provided is an error here.
func (s *DeploymentService) checkCaptureCapability() error {
	if s == nil || !s.ForwardEnabled {
		return d.ErrNotReady
	}
	switch s.Config.CaptureScope {
	case "platform-workspace", "runtime-workspace":
		// This does not approve workspace: PublishReadiness must still execute
		// all of its original grant, source, writer, owner and SQL checks.
		return nil
	case "six-part":
		if s.Runtime == nil || s.Runtime.Owner == nil {
			return d.ErrNotReady
		}
		binding := s.Runtime.Owner.productionSource
		if binding == nil || binding.service != s || binding.owner != s.Runtime.Owner || !binding.matchesCapturePlan() {
			return d.ErrNotReady
		}
		// Only an acknowledged, still-current readiness transaction produced
		// from the actual source/writer + provider dependencies can enable this.
		if s.publishedSixPartCapability() {
			return nil
		}
		return d.ErrNotReady
	default:
		return d.ErrNotReady
	}
}
