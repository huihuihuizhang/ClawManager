package systembackupcontrolevidence

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// This is the ONLY task source mapping intended for public Job/ConfigMap
// serialization. It carries no evidence body, credentials or inline sidecar.
// An independently authorized source reader resolves the exact registered
// immutable references, then Rebuild sends bytes directly into C encryption.
type CaptureLocator struct {
	Version       string              `json:"schema_version"`
	Expected      Expected            `json:"expected"`
	Generated     time.Time           `json:"generated_at"`
	Start         time.Time           `json:"coverage_started_at"`
	End           time.Time           `json:"coverage_ended_at"`
	Evidence      []EvidenceRef       `json:"evidence_refs"`
	SidecarSHA256 string              `json:"sidecar_sha256"`
	ProofsSHA256  string              `json:"proofs_sha256"`
	Finalization  *FinalizationPolicy `json:"finalization,omitempty"`
}

func (l CaptureLocator) Validate() error {
	if (l.Version != "system-backup-control-evidence-source.v1" || l.Finalization != nil) && (l.Version != "system-backup-control-evidence-source.v2" || l.Finalization == nil || !validFinalizationPolicy(*l.Finalization)) || !ValidScope(l.Expected.Scope) || !digestPattern.MatchString(l.Expected.ConfigSHA256) || !digestPattern.MatchString(l.Expected.SourceIdentitySHA256) || !validPin(l.Expected.SchemaRegistry) || !validPin(l.Expected.RedactionRegistry) || l.Start.IsZero() || l.End.Before(l.Start) || l.Generated.Before(l.End) || !digestPattern.MatchString(l.SidecarSHA256) || !digestPattern.MatchString(l.ProofsSHA256) || len(l.Evidence) < 13 || len(l.Evidence) > 256 {
		return ErrInvalid
	}
	last := ""
	for _, ref := range l.Evidence {
		if !validRef(ref) || ref.PublicID <= last {
			return ErrInvalid
		}
		last = ref.PublicID
	}
	return nil
}

func sourceLocator(expected Expected, sidecar Sidecar, entries []RegisteredEvidence, sidecarSHA, proofsSHA string) CaptureLocator {
	refs := make([]EvidenceRef, 0, len(entries))
	for _, entry := range entries {
		refs = append(refs, reference(entry))
	}
	return CaptureLocator{Version: "system-backup-control-evidence-source.v1", Expected: expected, Generated: sidecar.Generated, Start: sidecar.Start, End: sidecar.End, Evidence: refs, SidecarSHA256: sidecarSHA, ProofsSHA256: proofsSHA}
}

// Rebuild accepts only the COMPLETE exact registered original bodies matching
// this locator. It reconstructs no report, source record, missing group or
// owner success from defaults/SQL. Its output remains in memory for the two
// separately scoped original C streams; JSON serialization omits both bodies.
func Rebuild(ctx context.Context, locator CaptureLocator, entries []RegisteredEvidence) (PreparedSource, error) {
	if ctx == nil || ctx.Err() != nil || locator.Validate() != nil || locator.Finalization != nil || len(entries) != len(locator.Evidence) {
		return PreparedSource{}, ErrInvalid
	}
	entries = append([]RegisteredEvidence(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].PublicID < entries[j].PublicID })
	sidecar := Sidecar{Version: Version, Contract: "system-backup-plan.v12", Scope: locator.Expected.Scope, Generated: locator.Generated, Start: locator.Start, End: locator.End, Groups: map[string]Group{}, Owners: map[string]Owner{}, Warnings: []Warning{}}
	exclusionFound, redactionFound, sourceFound, ownerFound := false, false, false, false
	type groupChunk struct {
		proof GroupProof
		ref   EvidenceRef
	}
	chunks := map[string][]groupChunk{}
	for i, entry := range entries {
		if reference(entry) != locator.Evidence[i] || SHA256(entry.Payload) != entry.SHA256 {
			return PreparedSource{}, ErrInvalid
		}
		var kind struct {
			Version string `json:"schema_version"`
		}
		if json.Unmarshal(entry.Payload, &kind) != nil {
			return PreparedSource{}, ErrInvalid
		}
		switch kind.Version {
		case "system-backup-control-exclusion-proof.v1":
			var p ExclusionProof
			if exclusionFound || closed(entry.Payload, &p) != nil {
				return PreparedSource{}, ErrInvalid
			}
			exclusionFound = true
			namesSHA, err := namesHash(p.Excluded)
			if err != nil {
				return PreparedSource{}, err
			}
			sidecar.Exclusion = Exclusion{Version: p.Registry.Version, SHA256: p.Registry.SHA256, Count: uint64(len(p.Excluded)), NamesSHA256: namesSHA, Evidence: reference(entry)}
		case "system-backup-control-redaction-proof.v1":
			var p RedactionProof
			if redactionFound || closed(entry.Payload, &p) != nil {
				return PreparedSource{}, ErrInvalid
			}
			redactionFound = true
			sidecar.Redaction = Redaction{Version: p.Registry.Version, SHA256: p.Registry.SHA256, Applied: p.Applied, Rejected: p.Rejected, Evidence: reference(entry)}
		case "system-backup-source-control-exclusion.v1":
			var p SourceExclusionProof
			if sourceFound || closed(entry.Payload, &p) != nil {
				return PreparedSource{}, ErrInvalid
			}
			sourceFound = true
		case "system-backup-control-group-proof.v1":
			var p GroupProof
			if closed(entry.Payload, &p) != nil {
				return PreparedSource{}, ErrInvalid
			}
			chunks[p.Group] = append(chunks[p.Group], groupChunk{proof: p, ref: reference(entry)})
		case "system-backup-control-owner-proof.v1":
			var p OwnerProof
			if ownerFound || closed(entry.Payload, &p) != nil || p.Owner != "A" {
				return PreparedSource{}, ErrInvalid
			}
			ownerFound = true
			summary := p.SummarySHA256
			sidecar.Owners["A"] = Owner{Owner: "A", Status: "complete", Reason: "none", Summary: &summary, Evidence: []EvidenceRef{reference(entry)}}
		case "system-backup-control-owned-reports.v1":
			var p OwnedReportProof
			if closed(entry.Payload, &p) != nil || p.Owner != "B" && p.Owner != "C" && p.Owner != "D" {
				return PreparedSource{}, ErrInvalid
			}
			if _, exists := sidecar.Owners[p.Owner]; exists {
				return PreparedSource{}, ErrInvalid
			}
			summary := p.SummarySHA256
			refs := append([]EvidenceRef{reference(entry)}, p.BasisRefs...)
			refs = append(refs, p.Reports...)
			sidecar.Owners[p.Owner] = Owner{Owner: p.Owner, Status: "complete", Reason: "none", Summary: &summary, Evidence: refs}
		case "system-backup-verifier-result.v1", "system-backup-control-owned-basis-chunk.v1", "system-backup-control-original-source-seed.v1", "system-backup-control-registered-json-chunk.v1":
			// Original owner-schema bodies are validated and consumed only by
			// their exact owned proof in Verify below; unattached extras fail.
		default:
			return PreparedSource{}, ErrInvalid
		}
	}
	if !exclusionFound || !redactionFound || !sourceFound || !ownerFound {
		return PreparedSource{}, ErrInvalid
	}
	for name, list := range chunks {
		sort.Slice(list, func(i, j int) bool { return list[i].proof.ChunkIndex < list[j].proof.ChunkIndex })
		records := []TimedDigest{}
		refs := []EvidenceRef{}
		if len(list) < 1 || len(list) > MaxGroupEvidence {
			return PreparedSource{}, ErrInvalid
		}
		for index, chunk := range list {
			if chunk.proof.ChunkIndex != uint32(index) || chunk.proof.ChunkCount != uint32(len(list)) {
				return PreparedSource{}, ErrInvalid
			}
			records = append(records, chunk.proof.Records...)
			refs = append(refs, chunk.ref)
		}
		rolling, err := RollingHash(records)
		if err != nil {
			return PreparedSource{}, err
		}
		group := Group{Group: name, Count: uint64(len(records)), RollingSHA256: rolling, Evidence: refs}
		if len(records) > 0 {
			first, last := records[0].At, records[len(records)-1].At
			group.First, group.Last = &first, &last
		}
		sidecar.Groups[name] = group
	}
	for _, owner := range []string{"B", "C", "D"} {
		if _, exists := sidecar.Owners[owner]; !exists {
			sidecar.Owners[owner] = Owner{Owner: owner, Status: "incomplete", Reason: "evidence_missing", Evidence: []EvidenceRef{}}
		}
	}
	sidecarRaw, err := Canonical(sidecar)
	if err != nil {
		return PreparedSource{}, err
	}
	proofRaw, err := CanonicalProofs(ProofBundle{Version: "system-backup-control-evidence-proofs.v1", Scope: locator.Expected.Scope, Entries: entries})
	if err != nil {
		return PreparedSource{}, err
	}
	out := PreparedSource{Scope: locator.Expected.Scope, SidecarJSON: sidecarRaw, SidecarSHA256: SHA256(sidecarRaw), ProofsJSON: proofRaw, ProofsSHA256: SHA256(proofRaw), Locator: locator}
	if out.SidecarSHA256 != locator.SidecarSHA256 || out.ProofsSHA256 != locator.ProofsSHA256 || ValidatePrepared(ctx, out, locator.Expected) != nil {
		return PreparedSource{}, ErrInvalid
	}
	return out, nil
}
