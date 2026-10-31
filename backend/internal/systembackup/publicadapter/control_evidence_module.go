package publicadapter

import (
	"encoding/json"
	"reflect"
	"strconv"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

type ControlEvidenceModuleConfig struct {
	Revision        string
	Sidecar, Proofs CapturePartRequest
}

// The two registered original C streams are internal mysql storage parts.
// This pure constructor holds only the locator, never registered evidence bodies.
func NewControlEvidenceModule(cfg ControlEvidenceModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(cfg)
	var frozen ControlEvidenceModuleConfig
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	cfg = frozen
	requests := map[string]CapturePartRequest{ce.Part: cfg.Sidecar, ce.ProofPart: cfg.Proofs}
	for part, r := range requests {
		if r.Part != part || r.Category != ce.Part || r.Invocation.Request.Operation != ce.Operation || r.Invocation.Request.Binding.Path != part || r.Invocation.FormalCapture == nil || r.Invocation.FormalCapture.PermitDelivery == nil || r.Invocation.ProviderKey == nil || r.Workload.FormalMaterials == nil || r.Workload.Source.Name != "" || r.Workload.SourceSubPath != "" || !worker.ValidateRecordedInvocation(r.Invocation) || r.Invocation.FormalCapture.SourceConfigSHA256 != r.Invocation.Request.ControlEvidence.Expected.ConfigSHA256 {
			return zero, d.ErrNotReady
		}
	}
	if !reflect.DeepEqual(cfg.Sidecar.Invocation.Request.ControlEvidence, cfg.Proofs.Invocation.Request.ControlEvidence) {
		return zero, d.ErrNotReady
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: ce.Part, Owner: "D", Revision: cfg.Revision, Required: true, Parts: []CaptureModulePart{{ce.Part, ce.Part, "mysql", ce.Operation}, {ce.ProofPart, ce.Part, "mysql", ce.Operation}}}}
	if !validControlEvidenceDescriptor(registration.Descriptor) || cfg.Revision == "" {
		return zero, d.ErrNotReady
	}
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		if len(input.Parts) != 2 {
			return nil, d.ErrNotReady
		}
		out := make([]CapturePartRequest, 0, 2)
		seen := map[string]bool{}
		for _, selection := range input.Parts {
			r, ok := requests[selection.Part]
			if !ok || seen[selection.Part] || selection.Category != ce.Part || selection.Operation != ce.Operation || selection.RequestedPart != "mysql" {
				return nil, d.ErrNotReady
			}
			seen[selection.Part] = true
			bound, locator := r.Invocation.Request.Binding, r.Invocation.Request.ControlEvidence
			if bound.BackupID != input.Input.Authority.TaskPublicID || bound.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || bound.PartIndex != selection.PartIndex || bound.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) || r.Invocation.ProviderKey.Request.Context.PartIndex != strconv.FormatUint(uint64(selection.PartIndex), 10) || locator.Expected.Installation != input.Input.Authority.InstallationID || locator.Expected.ConfigSHA256 != input.Input.Authority.ConfigSHA256 {
				return nil, d.ErrNotReady
			}
			raw, _ := json.Marshal(r)
			var copy CapturePartRequest
			if json.Unmarshal(raw, &copy) != nil {
				return nil, d.ErrNotReady
			}
			out = append(out, copy)
		}
		return out, nil
	}
	return registration, nil
}

func validControlEvidenceDescriptor(descriptor CaptureModuleDescriptor) bool {
	reserved := descriptor.ID == ce.Part
	for _, part := range descriptor.Parts {
		reserved = reserved || part.Operation == ce.Operation || part.Part == ce.Part || part.Part == ce.ProofPart
	}
	if !reserved {
		return true
	}
	if descriptor.ID != ce.Part || descriptor.Owner != "D" || !descriptor.Required || descriptor.DependencyOnly || len(descriptor.Requires) != 0 || len(descriptor.Parts) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, part := range descriptor.Parts {
		if seen[part.Part] || part.Part != ce.Part && part.Part != ce.ProofPart || part.Category != ce.Part || part.RequestedPart != "mysql" || part.Operation != ce.Operation {
			return false
		}
		seen[part.Part] = true
	}
	return true
}

// Recheck raw registrations too: the catalog does not rely on callers choosing
// this constructor, and two independently valid locators are not one snapshot.
func validateControlEvidenceParts(in d.Input, parts []JobPart) error {
	var locator *ce.CaptureLocator
	count := 0
	for _, part := range parts {
		var invocation worker.Invocation
		if decodeStrict(part.InvocationJSON, &invocation) != nil {
			return d.ErrNotReady
		}
		if invocation.Request.Operation != ce.Operation {
			continue
		}
		actual := invocation.Request.ControlEvidence
		if actual == nil || actual.Expected.Installation != in.Authority.InstallationID || actual.Expected.ConfigSHA256 != in.Authority.ConfigSHA256 || locator != nil && !reflect.DeepEqual(locator, actual) {
			return d.ErrNotReady
		}
		locator = actual
		count++
	}
	if count != 0 && count != 2 {
		return d.ErrNotReady
	}
	return nil
}
