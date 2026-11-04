package quiesce

// Reference carried by the existing READ-ONLY whole-node observation request.
// The reader must open the native owner's durable anchor and independently
// reread actual original frozen cgroups/journal/FLOCK/process/mount identities
// before exempting any frozen writer from its existing complete FD/mmap scan.
// It grants no authority and exposes no stop/start/freeze method on NodeObserver.
// An authenticated lifecycle check-frozen response by itself does NOT authorize
// skipping the whole-node scan or trusting stale process membership.
type SharedRuntimeFrozenScope struct {
	Binding                                                                      ObservationBinding
	AgentPod                                                                     PodIdentity
	Anchor, OriginalSHA256, CohortSHA256, SourcePathsSHA256, NativeJournalSHA256 string
}

func (p *VerifiedSharedRuntimeNodeObservation) FrozenScope() (SharedRuntimeFrozenScope, error) {
	var zero SharedRuntimeFrozenScope
	if p == nil || p.response.Action != "check-frozen" || p.response.Phase != "frozen" {
		return zero, ErrNodeObservation
	}
	r := p.response
	return SharedRuntimeFrozenScope{Binding: r.Binding, AgentPod: p.originalRequest.AgentPod, Anchor: r.Anchor, OriginalSHA256: r.OriginalSHA256, CohortSHA256: r.CohortSHA256, SourcePathsSHA256: r.SourcePathsSHA256, NativeJournalSHA256: r.NativeJournalSHA256}, nil
}
