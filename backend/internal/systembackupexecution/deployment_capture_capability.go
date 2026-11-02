package systembackupexecution

import d "clawreef/internal/systembackupdispatch"

// This first structural batch grants no six-part capability. An attached plan
// proves only builder composition. Current taskless source observations and
// ordinary publisher dependencies must still be wired. Future positive checks
// must cover the complete actual writer set and its original observation window:
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
		// No positive branch or caller-controlled passed flag is introduced.
		return d.ErrNotReady
	default:
		return d.ErrNotReady
	}
}
