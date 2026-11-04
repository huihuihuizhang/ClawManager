package quiesce

import "encoding/json"

// Public comparison transcript from an already authenticated concrete native
// roundtrip. It cannot mint another opaque proof and contains no private native
// Agent OriginalRequests or controller credentials. Return a detached copy.
func (p *VerifiedSharedRuntimeNodeObservation) Request() SharedRuntimeNodeRequest {
	if p == nil {
		return SharedRuntimeNodeRequest{}
	}
	raw, err := json.Marshal(p.originalRequest)
	if err != nil {
		return SharedRuntimeNodeRequest{}
	}
	var out SharedRuntimeNodeRequest
	if json.Unmarshal(raw, &out) != nil {
		return SharedRuntimeNodeRequest{}
	}
	return out
}
