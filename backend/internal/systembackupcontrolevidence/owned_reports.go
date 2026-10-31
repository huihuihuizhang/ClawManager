package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// These envelopes remain DATA in their original v12 owner schema. A passed
// check is not capture, signing or publication authority. The concrete source
// producer and final artifact reader must independently derive the comparison
// values from the original authenticated payloads and original SQL journals.
type VerifierReport struct {
	Version    string          `json:"schema_version"`
	TargetType string          `json:"target_type"`
	Target     string          `json:"target_public_id"`
	Attempt    *uint64         `json:"attempt_no"`
	Category   string          `json:"category"`
	Mode       string          `json:"mode"`
	Checks     []VerifierCheck `json:"checks"`
}

type VerifierCheck struct {
	ID             string          `json:"id"`
	Status         string          `json:"status"`
	SkipReason     *string         `json:"skip_reason"`
	Expected       json.RawMessage `json:"expected"`
	Actual         json.RawMessage `json:"actual"`
	Evidence       *string         `json:"evidence_ref"`
	Warning        *string         `json:"warning_code"`
	Classification *string         `json:"check_classification"`
	Failure        string          `json:"failure_category"`
}

// Bind each owner to the exact original capture context and immutable original
// result identities, separately from the historical nine-group cutoff. No
// source row, credential, free-form message or mutable current locator occurs.
type OwnedReportBasis struct {
	CaptureContextSHA256 string           `json:"capture_context_sha256"`
	Parts                []OwnedPartBasis `json:"original_parts"`
}

type OwnedPartBasis struct {
	Part              string `json:"part"`
	Operation         string `json:"operation"`
	InvocationSHA256  string `json:"invocation_sha256"`
	CandidateSHA256   string `json:"candidate_sha256"`
	ResultSHA256      string `json:"result_sha256"`
	ResultEvidenceRef string `json:"result_evidence_ref"`
	CiphertextSHA256  string `json:"ciphertext_sha256"`
	EnvelopeSHA256    string `json:"envelope_sha256"`
	CiphertextBytes   int64  `json:"ciphertext_bytes"`
}

type OwnedReportProof struct {
	Version string `json:"schema_version"`
	Scope
	Owner                string        `json:"owner"`
	ConfigSHA256         string        `json:"config_sha256"`
	CoverageEndedAt      time.Time     `json:"coverage_ended_at"`
	ObservedAt           time.Time     `json:"observed_at"`
	CaptureContextSHA256 string        `json:"capture_context_sha256"`
	PartCount            uint64        `json:"original_part_count"`
	BasisRefs            []EvidenceRef `json:"original_part_basis_refs"`
	Reports              []EvidenceRef `json:"reports"`
	SummarySHA256        string        `json:"verifier_summary_hash"`
}

const OwnedPartsPerEvidence = 8

type OwnedPartBasisChunk struct {
	Version string `json:"schema_version"`
	Scope
	CaptureContextSHA256 string           `json:"capture_context_sha256"`
	Index                uint32           `json:"chunk_index"`
	Count                uint32           `json:"chunk_count"`
	Parts                []OwnedPartBasis `json:"original_parts"`
}

func ownedBasis(proof OwnedReportProof, entries map[string]RegisteredEvidence) (OwnedReportBasis, error) {
	basis := OwnedReportBasis{CaptureContextSHA256: proof.CaptureContextSHA256, Parts: []OwnedPartBasis{}}
	if proof.PartCount < 1 || proof.PartCount > 10000 || len(proof.BasisRefs) < 1 || len(proof.BasisRefs) != (int(proof.PartCount)+OwnedPartsPerEvidence-1)/OwnedPartsPerEvidence {
		return OwnedReportBasis{}, ErrInvalid
	}
	for index, ref := range proof.BasisRefs {
		entry, ok := entries[ref.PublicID]
		var chunk OwnedPartBasisChunk
		if !ok || reference(entry) != ref || entry.OwnerType != "backup" || entry.OwnerID != proof.Backup || entry.Type != "verifier_report" || SHA256(entry.Payload) != ref.SHA256 || closed(entry.Payload, &chunk) != nil || chunk.Version != "system-backup-control-owned-basis-chunk.v1" || chunk.Scope != proof.Scope || chunk.CaptureContextSHA256 != proof.CaptureContextSHA256 || chunk.Index != uint32(index) || chunk.Count != uint32(len(proof.BasisRefs)) || len(chunk.Parts) < 1 || len(chunk.Parts) > OwnedPartsPerEvidence || index < len(proof.BasisRefs)-1 && len(chunk.Parts) != OwnedPartsPerEvidence {
			return OwnedReportBasis{}, ErrInvalid
		}
		basis.Parts = append(basis.Parts, chunk.Parts...)
	}
	if uint64(len(basis.Parts)) != proof.PartCount || !validOwnerBasis(basis) {
		return OwnedReportBasis{}, ErrInvalid
	}
	return basis, nil
}

type OwnedReports struct {
	Owner      string
	ObservedAt time.Time
	Basis      OwnedReportBasis
	Reports    []RegisteredEvidence
}

// ProposedVerifierReport returns bounded owner-schema DATA for registration by
// the caller's real original authority transaction. It cannot prove that the
// comparisons ran, register a row, or grant source/provider/publication use.
func ProposedVerifierReport(scope Scope, owner string, report VerifierReport) (RegisteredEvidence, error) {
	entry, err := registered(scope, report)
	if err != nil {
		return RegisteredEvidence{}, err
	}
	if _, err = validateOwnerReport(scope, owner, entry.Payload); err != nil {
		return RegisteredEvidence{}, err
	}
	return entry, nil
}

func validOwnerBasis(b OwnedReportBasis) bool {
	if !digestPattern.MatchString(b.CaptureContextSHA256) || len(b.Parts) < 1 || len(b.Parts) > 10000 {
		return false
	}
	last := ""
	for _, part := range b.Parts {
		if part.Part <= last || part.Part == Part || part.Part == ProofPart || len(part.Part) > 128 || part.Operation == "" || len(part.Operation) > 128 || part.CiphertextBytes < 1 || !evidencePattern.MatchString(part.ResultEvidenceRef) {
			return false
		}
		for _, digest := range []string{part.InvocationSHA256, part.CandidateSHA256, part.ResultSHA256, part.CiphertextSHA256, part.EnvelopeSHA256} {
			if !digestPattern.MatchString(digest) {
				return false
			}
		}
		last = part.Part
	}
	return true
}

func ownerCategory(owner, category string) bool {
	switch owner {
	case "B":
		return category == "instances" || category == "teams" || category == "resources" || category == "skill_hub"
	case "C":
		return category == "artifact" || category == "catalog"
	case "D":
		return category == "control_plane" || category == "isolation"
	}
	return false
}

func validateOwnerReport(scope Scope, owner string, raw []byte) (VerifierReport, error) {
	var report VerifierReport
	if closed(raw, &report) != nil || report.Version != "system-backup-verifier-result.v1" || report.TargetType != "backup" || report.Target != scope.Backup || report.Attempt == nil || *report.Attempt != scope.Attempt || report.Mode != "backup_validate" || !ownerCategory(owner, report.Category) || len(report.Checks) < 1 || len(report.Checks) > 256 {
		return VerifierReport{}, ErrInvalid
	}
	last := ""
	for _, check := range report.Checks {
		if check.ID <= last || len(check.ID) > 256 || !strings.HasPrefix(check.ID, report.Category+".") || check.Status != "passed" || check.SkipReason != nil || check.Warning != nil || check.Classification != nil || check.Failure != "none" || check.Evidence == nil || !evidencePattern.MatchString(*check.Evidence) {
			return VerifierReport{}, ErrInvalid
		}
		var expected, actual map[string]json.RawMessage
		if len(check.Expected) < 2 || !bytes.Equal(check.Expected, check.Actual) || json.Unmarshal(check.Expected, &expected) != nil || json.Unmarshal(check.Actual, &actual) != nil || expected == nil || actual == nil || len(expected) < 1 || len(expected) > 8 {
			return VerifierReport{}, ErrInvalid
		}
		for key, value := range actual {
			switch key {
			case "hash":
				var digest string
				if json.Unmarshal(value, &digest) != nil || !digestPattern.MatchString(digest) {
					return VerifierReport{}, ErrInvalid
				}
			case "rows", "bytes", "count", "generation", "violations", "parts", "objects", "files":
				var count uint64
				if json.Unmarshal(value, &count) != nil {
					return VerifierReport{}, ErrInvalid
				}
			case "max_id":
				var count *uint64
				if json.Unmarshal(value, &count) != nil {
					return VerifierReport{}, ErrInvalid
				}
			default:
				return VerifierReport{}, ErrInvalid
			}
		}
		last = check.ID
	}
	return report, nil
}

func ownedSummary(proof OwnedReportProof, entries map[string]RegisteredEvidence) (string, error) {
	basis, basisErr := ownedBasis(proof, entries)
	if basisErr != nil || len(proof.Reports) < 1 || len(proof.Reports)+len(proof.BasisRefs) > 31 {
		return "", ErrInvalid
	}
	type summaryReport struct {
		Ref    EvidenceRef    `json:"ref"`
		Report VerifierReport `json:"report"`
	}
	reports := make([]summaryReport, 0, len(proof.Reports))
	seenChecks := map[string]bool{}
	requirements, requirementErr := RequiredOwnerChecks(proof.Owner, basis)
	if requirementErr != nil {
		return "", requirementErr
	}
	requiredChecks := map[string]OwnerCheckRequirement{}
	for _, required := range requirements {
		requiredChecks[required.ID] = required
	}
	requiredParts := map[string]bool{}
	for _, part := range basis.Parts {
		if _, exists := requiredParts[part.ResultEvidenceRef]; exists {
			return "", ErrInvalid
		}
		requiredParts[part.ResultEvidenceRef] = false
	}
	last := ""
	for _, ref := range proof.Reports {
		entry, ok := entries[ref.PublicID]
		if !ok || ref.PublicID <= last || entry.SHA256 != ref.SHA256 || entry.OwnerType != "backup" || entry.OwnerID != proof.Backup || entry.Type != "verifier_report" || SHA256(entry.Payload) != ref.SHA256 {
			return "", ErrInvalid
		}
		report, err := validateOwnerReport(proof.Scope, proof.Owner, entry.Payload)
		if err != nil {
			return "", err
		}
		for _, check := range report.Checks {
			if seenChecks[check.ID] {
				return "", ErrInvalid
			}
			seenChecks[check.ID] = true
			required, exists := requiredChecks[check.ID]
			if !exists || required.Category != report.Category || required.ResultEvidenceRef != *check.Evidence || !bytes.Equal(required.Expected, check.Expected) {
				return "", ErrInvalid
			}
			if _, exists := requiredParts[*check.Evidence]; !exists {
				return "", ErrInvalid
			}
			requiredParts[*check.Evidence] = true
		}
		reports = append(reports, summaryReport{ref, report})
		last = ref.PublicID
	}
	for _, seen := range requiredParts {
		if !seen {
			return "", ErrInvalid
		}
	}
	if len(seenChecks) != len(requiredChecks) {
		return "", ErrInvalid
	}
	raw, err := CanonicalProofs(struct {
		Scope    Scope            `json:"scope"`
		Owner    string           `json:"owner"`
		Config   string           `json:"config_sha256"`
		Cutoff   time.Time        `json:"coverage_ended_at"`
		Observed time.Time        `json:"observed_at"`
		Basis    OwnedReportBasis `json:"basis"`
		Reports  []summaryReport  `json:"reports"`
	}{proof.Scope, proof.Owner, proof.ConfigSHA256, proof.CoverageEndedAt, proof.ObservedAt, basis, reports})
	if err != nil {
		return "", err
	}
	return SHA256(raw), nil
}

// AssembleOwned produces NEW canonical plaintext before its one original C
// capture. It cannot mutate an existing C stream. Nine-group cutoff/proofs and
// A's summary remain byte-for-byte original; Generated reflects the later
// actual owner observations. The resulting bytes still require independent
// current Generate authority and final complete-artifact domain verification.
func AssembleOwned(ctx context.Context, base PreparedSource, generated time.Time, owners []OwnedReports) (ProposedSource, error) {
	if ValidatePrepared(ctx, base, base.Locator.Expected) != nil || len(owners) != 3 || generated.Before(base.Locator.Generated) {
		return ProposedSource{}, ErrInvalid
	}
	var sidecar Sidecar
	var bundle ProofBundle
	if closed(base.SidecarJSON, &sidecar) != nil || closedLimit(base.ProofsJSON, &bundle, MaxProofBytes) != nil {
		return ProposedSource{}, ErrInvalid
	}
	entries := map[string]RegisteredEvidence{}
	for _, entry := range bundle.Entries {
		entries[entry.PublicID] = entry
	}
	seen := map[string]bool{}
	if !validOwnerBasis(owners[0].Basis) {
		return ProposedSource{}, ErrInvalid
	}
	basisRaw, basisErr := CanonicalProofs(owners[0].Basis)
	if basisErr != nil {
		return ProposedSource{}, basisErr
	}
	basisRefs := []EvidenceRef{}
	basisCount := (len(owners[0].Basis.Parts) + OwnedPartsPerEvidence - 1) / OwnedPartsPerEvidence
	for index := 0; index < basisCount; index++ {
		end := (index + 1) * OwnedPartsPerEvidence
		if end > len(owners[0].Basis.Parts) {
			end = len(owners[0].Basis.Parts)
		}
		chunk := OwnedPartBasisChunk{Version: "system-backup-control-owned-basis-chunk.v1", Scope: sidecar.Scope, CaptureContextSHA256: owners[0].Basis.CaptureContextSHA256, Index: uint32(index), Count: uint32(basisCount), Parts: owners[0].Basis.Parts[index*OwnedPartsPerEvidence : end]}
		entry, err := registered(sidecar.Scope, chunk)
		if err != nil {
			return ProposedSource{}, ErrCapacity
		}
		entries[entry.PublicID] = entry
		basisRefs = append(basisRefs, reference(entry))
	}
	for _, owned := range owners {
		if seen[owned.Owner] || !ownerCategory(owned.Owner, map[string]string{"B": "instances", "C": "artifact", "D": "control_plane"}[owned.Owner]) || owned.ObservedAt.Before(sidecar.End) || owned.ObservedAt.After(generated) {
			return ProposedSource{}, ErrInvalid
		}
		seen[owned.Owner] = true
		ownedBasisRaw, err := CanonicalProofs(owned.Basis)
		if err != nil || !bytes.Equal(basisRaw, ownedBasisRaw) {
			return ProposedSource{}, ErrInvalid
		}
		proof := OwnedReportProof{Version: "system-backup-control-owned-reports.v1", Scope: sidecar.Scope, Owner: owned.Owner, ConfigSHA256: base.Locator.Expected.ConfigSHA256, CoverageEndedAt: sidecar.End, ObservedAt: owned.ObservedAt, CaptureContextSHA256: owned.Basis.CaptureContextSHA256, PartCount: uint64(len(owned.Basis.Parts)), BasisRefs: basisRefs, Reports: []EvidenceRef{}}
		for _, entry := range owned.Reports {
			if _, exists := entries[entry.PublicID]; exists {
				return ProposedSource{}, ErrInvalid
			}
			entries[entry.PublicID] = entry
			proof.Reports = append(proof.Reports, reference(entry))
		}
		sort.Slice(proof.Reports, func(i, j int) bool { return proof.Reports[i].PublicID < proof.Reports[j].PublicID })
		summary, err := ownedSummary(proof, entries)
		if err != nil {
			return ProposedSource{}, err
		}
		proof.SummarySHA256 = summary
		entry, err := registered(sidecar.Scope, proof)
		if err != nil {
			return ProposedSource{}, err
		}
		if _, exists := entries[entry.PublicID]; exists {
			return ProposedSource{}, ErrInvalid
		}
		entries[entry.PublicID] = entry
		refs := append([]EvidenceRef{reference(entry)}, proof.BasisRefs...)
		refs = append(refs, proof.Reports...)
		sidecar.Owners[owned.Owner] = Owner{Owner: owned.Owner, Status: "complete", Reason: "none", Summary: &summary, Evidence: refs}
	}
	sidecar.Generated = generated
	bundle.Entries = make([]RegisteredEvidence, 0, len(entries))
	for _, entry := range entries {
		bundle.Entries = append(bundle.Entries, entry)
	}
	sort.Slice(bundle.Entries, func(i, j int) bool { return bundle.Entries[i].PublicID < bundle.Entries[j].PublicID })
	if len(bundle.Entries) > 256 {
		return ProposedSource{}, ErrCapacity
	}
	sidecarRaw, err := Canonical(sidecar)
	if err != nil {
		return ProposedSource{}, err
	}
	proofRaw, err := CanonicalProofs(bundle)
	if err != nil {
		return ProposedSource{}, err
	}
	if _, err = Verify(ctx, sidecarRaw, proofRaw, base.Locator.Expected); err != nil {
		return ProposedSource{}, err
	}
	locator := sourceLocator(base.Locator.Expected, sidecar, bundle.Entries, SHA256(sidecarRaw), SHA256(proofRaw))
	return ProposedSource{Prepared: PreparedSource{Scope: sidecar.Scope, SidecarJSON: sidecarRaw, SidecarSHA256: SHA256(sidecarRaw), ProofsJSON: proofRaw, ProofsSHA256: SHA256(proofRaw), Locator: locator}, Evidence: bundle.Entries}, nil
}
