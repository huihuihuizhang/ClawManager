package systembackupexecution

import (
	"reflect"
	"sort"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

// This set is derived from already materialized original business Invocation
// bytes. It is not a caller-supplied context or a hash projection of Source.
func productionFinalizationPolicy(contextSHA string, parts []b.JobPart) (ce.FinalizationPolicy, error) {
	zero := ce.FinalizationPolicy{}
	if !formalCandidateDigest(contextSHA) {
		return zero, d.ErrNotReady
	}
	policy := ce.FinalizationPolicy{Version: ce.FinalizationPolicyVersion, ChecksVersion: ce.OwnedChecksVersion, CaptureContextSHA256: contextSHA, Parts: []ce.FinalizationPart{}}
	seen := map[string]bool{}
	control := map[string]bool{}
	for _, part := range parts {
		var invocation worker.Invocation
		if seen[part.Part] || part.Part == "" || decodeMetadataCanonical(part.InvocationJSON, &invocation) != nil || hash(part.InvocationJSON) != part.InvocationSHA256 || !worker.ValidateRecordedInvocation(invocation) || invocation.Request.Binding.Path != part.Part || invocation.Request.Binding.CaptureContextHash != contextSHA || invocation.ProviderKey == nil || invocation.ProviderKey.Request.Context.CaptureContextHash != contextSHA {
			return zero, d.ErrNotReady
		}
		seen[part.Part] = true
		if part.Part == ce.Part || part.Part == ce.ProofPart {
			if invocation.Request.Operation != ce.Operation || invocation.Request.ControlEvidence == nil {
				return zero, d.ErrNotReady
			}
			control[part.Part] = true
			continue
		}
		if invocation.Request.Operation == ce.Operation || invocation.Request.ControlEvidence != nil {
			return zero, d.ErrNotReady
		}
		policy.Parts = append(policy.Parts, ce.FinalizationPart{Part: part.Part, Operation: invocation.Request.Operation, InvocationSHA256: part.InvocationSHA256})
	}
	if len(control) != 2 || len(policy.Parts) == 0 {
		return zero, d.ErrNotReady
	}
	sort.Slice(policy.Parts, func(i, j int) bool { return policy.Parts[i].Part < policy.Parts[j].Part })
	return policy, nil
}

func validateProductionControlSeeds(in d.Input, source b.SourceInventory, metadata productionCaptureMetadata, discovery b.Discovery) error {
	if metadata.ControlEvidence.Version != "system-backup-control-evidence-source.v1" || metadata.ControlEvidence.Finalization != nil || metadata.ControlEvidence.Validate() != nil {
		return d.ErrNotReady
	}
	point, err := productionModuleContext(in, source, discovery.HoldUntil, discovery.Writers, "")
	if err != nil {
		return err
	}
	policy, err := productionFinalizationPolicy(point.CaptureContextSHA256, discovery.Parts)
	if err != nil {
		return err
	}
	for _, part := range discovery.Parts {
		if part.Part != ce.Part && part.Part != ce.ProofPart {
			continue
		}
		var invocation worker.Invocation
		if decodeMetadataCanonical(part.InvocationJSON, &invocation) != nil || invocation.Request.ControlEvidence == nil {
			return d.ErrNotReady
		}
		seed := invocation.Request.ControlEvidence
		base, err := seed.BaseSnapshot()
		if err != nil || seed.Version != "system-backup-control-evidence-source.v2" || seed.Finalization == nil || !reflect.DeepEqual(base, metadata.ControlEvidence) || !reflect.DeepEqual(*seed.Finalization, policy) {
			return d.ErrNotReady
		}
	}
	return nil
}
