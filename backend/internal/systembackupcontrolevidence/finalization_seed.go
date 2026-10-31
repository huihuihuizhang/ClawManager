package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"time"
)

type finalizationSeedProof struct {
	Version string `json:"schema_version"`
	Scope
	Seed RegisteredJSON `json:"original_source_seed"`
}

func finalizedSeed(entries map[string]RegisteredEvidence) (CaptureLocator, RegisteredEvidence, []EvidenceRef, error) {
	var root RegisteredEvidence
	var proof finalizationSeedProof
	for _, entry := range entries {
		var kind struct {
			Version string `json:"schema_version"`
		}
		if json.Unmarshal(entry.Payload, &kind) != nil {
			return CaptureLocator{}, root, nil, ErrInvalid
		}
		if kind.Version != "system-backup-control-original-source-seed.v1" {
			continue
		}
		if root.PublicID != "" || closed(entry.Payload, &proof) != nil || proof.Seed.Kind != "original-source-seed" {
			return CaptureLocator{}, root, nil, ErrInvalid
		}
		root = entry
	}
	if root.PublicID == "" {
		return CaptureLocator{}, root, nil, ErrInvalid
	}
	raw, err := readRegisteredJSON(proof.Scope, proof.Seed, entries)
	if err != nil {
		return CaptureLocator{}, root, nil, err
	}
	var seed CaptureLocator
	if closed(raw, &seed) != nil || seed.Validate() != nil || seed.Finalization == nil || proof.Scope != seed.Expected.Scope || root.OwnerType != "backup" || root.OwnerID != proof.Backup || root.Type != "verifier_report" {
		return CaptureLocator{}, root, nil, ErrInvalid
	}
	return seed, root, proof.Seed.Chunks, nil
}

// The complete encrypted proof stream carries the original frozen seed too.
// Its JSON chunks are content-addressed and consume no self-referential final
// digest: the seed pins ONLY the prior historical snapshot and business set.
func AssembleFinalized(ctx context.Context, seed CaptureLocator, base PreparedSource, generated time.Time, owners []OwnedReports) (ProposedSource, error) {
	baseLocator, err := seed.BaseSnapshot()
	if err != nil || seed.Finalization == nil {
		return ProposedSource{}, ErrInvalid
	}
	left, _ := Canonical(baseLocator)
	right, _ := Canonical(base.Locator)
	if !bytes.Equal(left, right) {
		return ProposedSource{}, ErrInvalid
	}
	proposal, err := AssembleOwned(ctx, base, generated, owners)
	if err != nil {
		return ProposedSource{}, err
	}
	raw, err := Canonical(seed)
	if err != nil {
		return ProposedSource{}, err
	}
	descriptor, chunks, err := proposeRegisteredJSON(seed.Expected.Scope, "original-source-seed", raw)
	if err != nil {
		return ProposedSource{}, err
	}
	root, err := registered(seed.Expected.Scope, finalizationSeedProof{Version: "system-backup-control-original-source-seed.v1", Scope: seed.Expected.Scope, Seed: descriptor})
	if err != nil {
		return ProposedSource{}, ErrCapacity
	}
	entries := append(append([]RegisteredEvidence{}, proposal.Evidence...), chunks...)
	entries = append(entries, root)
	sort.Slice(entries, func(i, j int) bool { return entries[i].PublicID < entries[j].PublicID })
	if len(entries) > 256 {
		return ProposedSource{}, ErrCapacity
	}
	proofs, err := CanonicalProofs(ProofBundle{Version: "system-backup-control-evidence-proofs.v1", Scope: seed.Expected.Scope, Entries: entries})
	if err != nil {
		return ProposedSource{}, err
	}
	clear(proposal.Prepared.ProofsJSON)
	proposal.Prepared.ProofsJSON = proofs
	proposal.Prepared.ProofsSHA256 = SHA256(proofs)
	proposal.Prepared.Locator.ProofsSHA256 = SHA256(proofs)
	proposal.Prepared.Locator.Evidence = []EvidenceRef{}
	for _, entry := range entries {
		proposal.Prepared.Locator.Evidence = append(proposal.Prepared.Locator.Evidence, reference(entry))
	}
	proposal.Evidence = entries
	if VerifyFinalizedPrepared(ctx, seed, proposal.Prepared) != nil {
		return ProposedSource{}, ErrInvalid
	}
	return proposal, nil
}

func verifySeedBasis(ctx context.Context, seed CaptureLocator, after Sidecar, entries map[string]RegisteredEvidence) error {
	if seed.Validate() != nil || seed.Finalization == nil || after.Scope != seed.Expected.Scope || !after.Start.Equal(seed.Start) || !after.End.Equal(seed.End) || after.Generated.Before(seed.Generated) {
		return ErrInvalid
	}
	base, _ := seed.BaseSnapshot()
	baseEntries := []RegisteredEvidence{}
	for _, ref := range base.Evidence {
		entry, ok := entries[ref.PublicID]
		if !ok || reference(entry) != ref {
			return ErrInvalid
		}
		baseEntries = append(baseEntries, entry)
	}
	prepared, err := Rebuild(ctx, base, baseEntries)
	if err != nil {
		return err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	var before Sidecar
	if closed(prepared.SidecarJSON, &before) != nil {
		return ErrInvalid
	}
	beforeSHA, err := OwnerASummary(before)
	if err != nil {
		return err
	}
	afterSHA, err := OwnerASummary(after)
	if err != nil || beforeSHA != afterSHA {
		return ErrInvalid
	}
	for _, owner := range []string{"B", "C", "D"} {
		section := after.Owners[owner]
		if section.Status != "complete" || len(section.Evidence) < 2 {
			return ErrInvalid
		}
		entry, ok := entries[section.Evidence[0].PublicID]
		var proof OwnedReportProof
		if !ok || closed(entry.Payload, &proof) != nil {
			return ErrInvalid
		}
		basis, err := ownedBasis(proof, entries)
		if err != nil || basis.CaptureContextSHA256 != seed.Finalization.CaptureContextSHA256 || len(basis.Parts) != len(seed.Finalization.Parts) {
			return ErrInvalid
		}
		for index, part := range seed.Finalization.Parts {
			actual := basis.Parts[index]
			if actual.Part != part.Part || actual.Operation != part.Operation || actual.InvocationSHA256 != part.InvocationSHA256 {
				return ErrInvalid
			}
		}
	}
	return nil
}

func VerifyFinalizedBytes(ctx context.Context, seed CaptureLocator, sidecarRaw, proofRaw []byte) (PreparedSource, error) {
	var sidecar Sidecar
	var bundle ProofBundle
	if closed(sidecarRaw, &sidecar) != nil || closedLimit(proofRaw, &bundle, MaxProofBytes) != nil {
		return PreparedSource{}, ErrInvalid
	}
	final := sourceLocator(seed.Expected, sidecar, bundle.Entries, SHA256(sidecarRaw), SHA256(proofRaw))
	prepared, err := VerifyFinalized(ctx, seed, final, bundle.Entries)
	if err != nil || !bytes.Equal(prepared.SidecarJSON, sidecarRaw) || !bytes.Equal(prepared.ProofsJSON, proofRaw) {
		clear(prepared.SidecarJSON)
		clear(prepared.ProofsJSON)
		return PreparedSource{}, ErrInvalid
	}
	return prepared, nil
}

func OriginalOwnedBasis(ctx context.Context, seed CaptureLocator, prepared PreparedSource) (OwnedReportBasis, error) {
	if VerifyFinalizedPrepared(ctx, seed, prepared) != nil {
		return OwnedReportBasis{}, ErrInvalid
	}
	var sidecar Sidecar
	var bundle ProofBundle
	if closed(prepared.SidecarJSON, &sidecar) != nil || closedLimit(prepared.ProofsJSON, &bundle, MaxProofBytes) != nil {
		return OwnedReportBasis{}, ErrInvalid
	}
	entries := map[string]RegisteredEvidence{}
	for _, entry := range bundle.Entries {
		entries[entry.PublicID] = entry
	}
	owner := sidecar.Owners["D"]
	if len(owner.Evidence) < 1 {
		return OwnedReportBasis{}, ErrInvalid
	}
	var proof OwnedReportProof
	if closed(entries[owner.Evidence[0].PublicID].Payload, &proof) != nil {
		return OwnedReportBasis{}, ErrInvalid
	}
	return ownedBasis(proof, entries)
}
