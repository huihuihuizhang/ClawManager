package publicadapter

import (
	"encoding/json"
	"strconv"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	d "clawreef/internal/systembackupdispatch"
)

func NewCaptureDescriptionModule(revision string, request CapturePartRequest) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(request)
	var frozen CapturePartRequest
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	r := frozen
	if revision == "" || r.Part != cd.Part || r.Category != cd.Part || r.Invocation.Request.Operation != cd.Operation || r.Invocation.Request.CaptureDescription == nil || r.Invocation.Request.CaptureDescription.Validate() != nil || !worker.ValidateRecordedInvocation(r.Invocation) || r.Invocation.FormalCapture == nil || r.Invocation.FormalCapture.PermitDelivery == nil || r.Invocation.ProviderKey == nil || r.Workload.FormalMaterials == nil || r.Workload.Source.Name != "" || r.Workload.SourceSubPath != "" {
		return zero, d.ErrNotReady
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: cd.Part, Owner: "A", Revision: revision, Required: true, Parts: []CaptureModulePart{{cd.Part, cd.Part, "mysql", cd.Operation}}}}
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		if len(input.Parts) != 1 {
			return nil, d.ErrNotReady
		}
		p := input.Parts[0]
		b := r.Invocation.Request.Binding
		if p.Part != cd.Part || p.Category != cd.Part || p.Operation != cd.Operation || p.RequestedPart != "mysql" || b.BackupID != input.Input.Authority.TaskPublicID || b.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || b.PartIndex != p.PartIndex || b.CaptureContextHash != input.Context.CaptureContextSHA256 || r.Invocation.FormalCapture.SourceConfigSHA256 != input.Input.Authority.ConfigSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) {
			return nil, d.ErrNotReady
		}
		var copy CapturePartRequest
		if json.Unmarshal(raw, &copy) != nil {
			return nil, d.ErrNotReady
		}
		return []CapturePartRequest{copy}, nil
	}
	return registration, nil
}

func validCaptureDescriptionDescriptor(d CaptureModuleDescriptor) bool {
	reserved := d.ID == cd.Part
	for _, p := range d.Parts {
		reserved = reserved || p.Part == cd.Part || p.Operation == cd.Operation
	}
	if !reserved {
		return true
	}
	return d.ID == cd.Part && d.Owner == "A" && d.Required && !d.DependencyOnly && len(d.Requires) == 0 && len(d.Parts) == 1 && d.Parts[0] == (CaptureModulePart{cd.Part, cd.Part, "mysql", cd.Operation})
}
