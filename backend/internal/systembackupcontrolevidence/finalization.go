package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"encoding/json"
)

const FinalizationPolicyVersion = "system-backup-control-owned-finalization.v1"
const OwnedChecksVersion = "system-backup-original-owned-checks.v1"

// V2 freezes the COMPLETE base snapshot hashes, capture context, business
// invocation identities and concrete owner-check policy before any CE Job.
// It never makes a fixed digest optional. Its later one-time source seal binds
// a SECOND exact v1 locator for complete owners; no prior C bytes are edited.
type FinalizationPolicy struct {
	Version              string             `json:"schema_version"`
	ChecksVersion        string             `json:"owned_checks_version"`
	CaptureContextSHA256 string             `json:"capture_context_sha256"`
	Parts                []FinalizationPart `json:"original_business_parts"`
}

type FinalizationPart struct {
	Part             string `json:"part"`
	Operation        string `json:"operation"`
	InvocationSHA256 string `json:"invocation_sha256"`
}

func validFinalizationPolicy(p FinalizationPolicy) bool {
	if p.Version != FinalizationPolicyVersion || p.ChecksVersion != OwnedChecksVersion || !digestPattern.MatchString(p.CaptureContextSHA256) || len(p.Parts) < 1 || len(p.Parts) > 10000 {
		return false
	}
	last := ""
	for _, part := range p.Parts {
		if part.Part <= last || part.Part == Part || part.Part == ProofPart || len(part.Part) > 128 || !digestPattern.MatchString(part.InvocationSHA256) {
			return false
		}
		switch part.Operation {
		case "capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", "capture-team-redis", "capture-team-objects":
		default:
			return false
		}
		last = part.Part
	}
	_, err := Canonical(p)
	return err == nil
}

func RequireOwnedFinalization(base CaptureLocator, policy FinalizationPolicy) (CaptureLocator, error) {
	if base.Validate() != nil || base.Version != "system-backup-control-evidence-source.v1" || base.Finalization != nil || !validFinalizationPolicy(policy) {
		return CaptureLocator{}, ErrInvalid
	}
	raw, err := Canonical(policy)
	if err != nil {
		return CaptureLocator{}, err
	}
	var frozen FinalizationPolicy
	if closed(raw, &frozen) != nil {
		return CaptureLocator{}, ErrInvalid
	}
	baseRaw, err := Canonical(base)
	if err != nil {
		return CaptureLocator{}, err
	}
	base = CaptureLocator{}
	if closed(baseRaw, &base) != nil {
		return CaptureLocator{}, ErrInvalid
	}
	base.Version = "system-backup-control-evidence-source.v2"
	base.Finalization = &frozen
	return base, nil
}

func (l CaptureLocator) BaseSnapshot() (CaptureLocator, error) {
	if l.Validate() != nil {
		return CaptureLocator{}, ErrInvalid
	}
	l.Version = "system-backup-control-evidence-source.v1"
	l.Finalization = nil
	return l, nil
}

type FinalizedSourceSeal struct {
	Version string `json:"schema_version"`
	Scope
	SeedSHA256 string         `json:"original_seed_sha256"`
	Locator    RegisteredJSON `json:"final_locator"`
}

type FinalizedSourceRegistration struct {
	Seal          RegisteredEvidence
	LocatorChunks []RegisteredEvidence
}

func FinalizedSourceEvidenceID(seed CaptureLocator) (string, error) {
	if seed.Validate() != nil || seed.Finalization == nil {
		return "", ErrInvalid
	}
	raw, err := Canonical(seed)
	if err != nil {
		return "", err
	}
	return "sev_ce_final_" + SHA256(raw), nil
}

// VerifyFinalized consumes all base and owned bodies from the artifact/source
// response. Missing bodies are never repaired from a database. Original
// concrete owner readers remain responsible for proving their actual values;
// this deterministic check enforces their full bound identity set and time.
func VerifyFinalized(ctx context.Context, seed CaptureLocator, final CaptureLocator, entries []RegisteredEvidence) (PreparedSource, error) {
	if seed.Validate() != nil || seed.Finalization == nil || final.Validate() != nil || final.Finalization != nil || final.Expected != seed.Expected || !final.Start.Equal(seed.Start) || !final.End.Equal(seed.End) || final.Generated.Before(seed.Generated) {
		return PreparedSource{}, ErrInvalid
	}
	base, err := seed.BaseSnapshot()
	if err != nil {
		return PreparedSource{}, err
	}
	byID := map[string]RegisteredEvidence{}
	for _, entry := range entries {
		if _, exists := byID[entry.PublicID]; exists {
			return PreparedSource{}, ErrInvalid
		}
		byID[entry.PublicID] = entry
	}
	storedSeed, _, _, seedErr := finalizedSeed(byID)
	expectedSeedRaw, expectedSeedErr := Canonical(seed)
	storedSeedRaw, storedSeedErr := Canonical(storedSeed)
	if seedErr != nil || expectedSeedErr != nil || storedSeedErr != nil || !bytes.Equal(expectedSeedRaw, storedSeedRaw) {
		return PreparedSource{}, ErrInvalid
	}
	baseEntries := make([]RegisteredEvidence, 0, len(base.Evidence))
	for _, ref := range base.Evidence {
		entry, ok := byID[ref.PublicID]
		if !ok || reference(entry) != ref {
			return PreparedSource{}, ErrInvalid
		}
		baseEntries = append(baseEntries, entry)
	}
	original, err := Rebuild(ctx, base, baseEntries)
	if err != nil {
		return PreparedSource{}, err
	}
	defer clear(original.SidecarJSON)
	defer clear(original.ProofsJSON)
	complete, err := Rebuild(ctx, final, entries)
	if err != nil {
		return PreparedSource{}, err
	}
	var before, after Sidecar
	if closed(original.SidecarJSON, &before) != nil || closed(complete.SidecarJSON, &after) != nil {
		return PreparedSource{}, ErrInvalid
	}
	beforeSummary, err := OwnerASummary(before)
	if err != nil {
		return PreparedSource{}, err
	}
	afterSummary, err := OwnerASummary(after)
	if err != nil || beforeSummary != afterSummary {
		return PreparedSource{}, ErrInvalid
	}
	for _, owner := range []string{"B", "C", "D"} {
		section := after.Owners[owner]
		if section.Status != "complete" || len(section.Evidence) < 2 {
			return PreparedSource{}, ErrInvalid
		}
		var proof OwnedReportProof
		entry := byID[section.Evidence[0].PublicID]
		if closed(entry.Payload, &proof) != nil {
			return PreparedSource{}, ErrInvalid
		}
		basis, basisErr := ownedBasis(proof, byID)
		if basisErr != nil || basis.CaptureContextSHA256 != seed.Finalization.CaptureContextSHA256 || len(basis.Parts) != len(seed.Finalization.Parts) {
			return PreparedSource{}, ErrInvalid
		}
		for index, part := range seed.Finalization.Parts {
			actual := basis.Parts[index]
			if actual.Part != part.Part || actual.Operation != part.Operation || actual.InvocationSHA256 != part.InvocationSHA256 {
				return PreparedSource{}, ErrInvalid
			}
		}
	}
	return complete, nil
}

func SealFinalizedSource(ctx context.Context, seed CaptureLocator, final CaptureLocator, entries []RegisteredEvidence) (FinalizedSourceRegistration, error) {
	prepared, err := VerifyFinalized(ctx, seed, final, entries)
	if err != nil {
		return FinalizedSourceRegistration{}, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	id, err := FinalizedSourceEvidenceID(seed)
	if err != nil {
		return FinalizedSourceRegistration{}, err
	}
	raw, err := Canonical(seed)
	if err != nil {
		return FinalizedSourceRegistration{}, err
	}
	finalRaw, err := Canonical(final)
	if err != nil {
		return FinalizedSourceRegistration{}, err
	}
	locator, locatorChunks, err := proposeRegisteredJSON(seed.Expected.Scope, "final-source-locator", finalRaw)
	if err != nil {
		return FinalizedSourceRegistration{}, err
	}
	seal := FinalizedSourceSeal{Version: "system-backup-control-finalized-source-seal.v1", Scope: seed.Expected.Scope, SeedSHA256: SHA256(raw), Locator: locator}
	payload, err := Canonical(seal)
	if err != nil || len(payload) > 8192 {
		return FinalizedSourceRegistration{}, ErrCapacity
	}
	return FinalizedSourceRegistration{Seal: RegisteredEvidence{PublicID: id, SHA256: SHA256(payload), OwnerType: "backup", OwnerID: seed.Expected.Backup, Type: "verifier_report", Payload: payload}, LocatorChunks: locatorChunks}, nil
}

func FinalizedSourceReferences(seed CaptureLocator, entry RegisteredEvidence) ([]EvidenceRef, error) {
	id, err := FinalizedSourceEvidenceID(seed)
	if err != nil || entry.PublicID != id || entry.OwnerType != "backup" || entry.OwnerID != seed.Expected.Backup || entry.Type != "verifier_report" || SHA256(entry.Payload) != entry.SHA256 {
		return nil, ErrInvalid
	}
	var seal FinalizedSourceSeal
	if closed(entry.Payload, &seal) != nil || seal.Version != "system-backup-control-finalized-source-seal.v1" || seal.Scope != seed.Expected.Scope || seal.Locator.Kind != "final-source-locator" {
		return nil, ErrInvalid
	}
	raw, err := Canonical(seed)
	if err != nil || seal.SeedSHA256 != SHA256(raw) {
		return nil, ErrInvalid
	}
	return append([]EvidenceRef{}, seal.Locator.Chunks...), nil
}

func ReadFinalizedSourceSeal(seed CaptureLocator, entry RegisteredEvidence, chunks ...RegisteredEvidence) (CaptureLocator, error) {
	refs, err := FinalizedSourceReferences(seed, entry)
	if err != nil || len(refs) != len(chunks) {
		return CaptureLocator{}, ErrInvalid
	}
	byID := map[string]RegisteredEvidence{}
	for index, chunk := range chunks {
		if reference(chunk) != refs[index] {
			return CaptureLocator{}, ErrInvalid
		}
		byID[chunk.PublicID] = chunk
	}
	var seal FinalizedSourceSeal
	if closed(entry.Payload, &seal) != nil {
		return CaptureLocator{}, ErrInvalid
	}
	raw, err := readRegisteredJSON(seed.Expected.Scope, seal.Locator, byID)
	if err != nil {
		return CaptureLocator{}, err
	}
	var final CaptureLocator
	if closed(raw, &final) != nil || final.Validate() != nil || final.Finalization != nil {
		return CaptureLocator{}, ErrInvalid
	}
	// Full body/basis reconstruction is still mandatory after loading entries.
	baseExpected, _ := json.Marshal(seed.Expected)
	finalExpected, _ := json.Marshal(final.Expected)
	if !bytes.Equal(baseExpected, finalExpected) || !final.Start.Equal(seed.Start) || !final.End.Equal(seed.End) || final.Generated.Before(seed.Generated) {
		return CaptureLocator{}, ErrInvalid
	}
	return final, nil
}

func VerifyFinalizedPrepared(ctx context.Context, seed CaptureLocator, prepared PreparedSource) error {
	if prepared.Scope != seed.Expected.Scope || SHA256(prepared.SidecarJSON) != prepared.SidecarSHA256 || SHA256(prepared.ProofsJSON) != prepared.ProofsSHA256 || prepared.SidecarSHA256 != prepared.Locator.SidecarSHA256 || prepared.ProofsSHA256 != prepared.Locator.ProofsSHA256 {
		return ErrInvalid
	}
	var bundle ProofBundle
	if closedLimit(prepared.ProofsJSON, &bundle, MaxProofBytes) != nil {
		return ErrInvalid
	}
	verified, err := VerifyFinalized(ctx, seed, prepared.Locator, bundle.Entries)
	defer clear(verified.SidecarJSON)
	defer clear(verified.ProofsJSON)
	if err != nil || !bytes.Equal(verified.SidecarJSON, prepared.SidecarJSON) || !bytes.Equal(verified.ProofsJSON, prepared.ProofsJSON) {
		return ErrInvalid
	}
	return nil
}
