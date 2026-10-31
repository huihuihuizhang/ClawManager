package systembackupcontrolevidence

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Snapshot is DATA from the concrete original RR SQL collector, never a task
// permission or an offline success flag. Its proof proposals must be registered
// and read back in the original authorized SQL transaction before a caller
// freezes PreparedSource in the original encrypted execution plan.
type Snapshot struct {
	Expected               Expected
	Start, End, Generated  time.Time
	ExcludedControlObjects []string
	SourceExclusion        RegisteredEvidence
	Groups                 map[string][]TimedDigest
}
type ProposedSource struct {
	Prepared PreparedSource
	Evidence []RegisteredEvidence
}

func registered(scope Scope, payload any) (RegisteredEvidence, error) {
	raw, err := Canonical(payload)
	if err != nil || len(raw) > 8192 {
		return RegisteredEvidence{}, ErrInvalid
	}
	sum := SHA256(raw)
	id := "sev_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("system-backup-control-proof.v1\x00"+scope.Installation+"\x00"+scope.Backup+"\x00"+sum)).String()
	return RegisteredEvidence{PublicID: id, SHA256: sum, OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: raw}, nil
}
func reference(e RegisteredEvidence) EvidenceRef { return EvidenceRef{e.PublicID, e.SHA256} }

// Assemble is a pure deterministic projection. It cannot mark B/C/D complete
// or invent their owned evidence. They remain explicitly incomplete until
// their concrete original producers supply independently validated reports.
func Assemble(ctx context.Context, input Snapshot) (ProposedSource, error) {
	expected := input.Expected
	if ctx == nil || ctx.Err() != nil || !ValidScope(expected.Scope) || input.Start.IsZero() || input.End.Before(input.Start) || input.Generated.Before(input.End) || len(input.Groups) != len(groups) {
		return ProposedSource{}, ErrInvalid
	}
	namesSHA, err := namesHash(input.ExcludedControlObjects)
	if err != nil {
		return ProposedSource{}, err
	}
	exclusion, err := registered(expected.Scope, ExclusionProof{Version: "system-backup-control-exclusion-proof.v1", Scope: expected.Scope, Registry: expected.SchemaRegistry, Excluded: append([]string(nil), input.ExcludedControlObjects...), Included: []string{}, SourceEvidence: reference(input.SourceExclusion)})
	if err != nil {
		return ProposedSource{}, err
	}
	projectionRaw, _ := Canonical(ProjectionColumns())
	redaction, err := registered(expected.Scope, RedactionProof{Version: "system-backup-control-redaction-proof.v1", Scope: expected.Scope, Registry: expected.RedactionRegistry, Applied: true, Rejected: 0, ProjectionSHA256: SHA256(projectionRaw)})
	if err != nil {
		return ProposedSource{}, err
	}
	entries := []RegisteredEvidence{input.SourceExclusion, exclusion, redaction}
	sidecar := Sidecar{Version: Version, Contract: "system-backup-plan.v12", Scope: expected.Scope, Generated: input.Generated, Start: input.Start, End: input.End, Exclusion: Exclusion{Version: expected.SchemaRegistry.Version, SHA256: expected.SchemaRegistry.SHA256, Count: uint64(len(input.ExcludedControlObjects)), NamesSHA256: namesSHA, Evidence: reference(exclusion)}, Redaction: Redaction{Version: expected.RedactionRegistry.Version, SHA256: expected.RedactionRegistry.SHA256, Applied: true, Rejected: 0, Evidence: reference(redaction)}, Groups: map[string]Group{}, Owners: map[string]Owner{}, Warnings: []Warning{}}
	for _, name := range groups {
		records, ok := input.Groups[name]
		if !ok || records == nil {
			return ProposedSource{}, ErrInvalid
		}
		if len(records) > MaxGroupRecords {
			return ProposedSource{}, ErrCapacity
		}
		refs := []EvidenceRef{}
		count := (len(records) + RecordsPerEvidence - 1) / RecordsPerEvidence
		if count == 0 {
			count = 1
		}
		for chunk := 0; chunk < count; chunk++ {
			end := (chunk + 1) * RecordsPerEvidence
			if end > len(records) {
				end = len(records)
			}
			proof, err := registered(expected.Scope, GroupProof{Version: "system-backup-control-group-proof.v1", Scope: expected.Scope, Group: name, ChunkIndex: uint32(chunk), ChunkCount: uint32(count), Start: input.Start, End: input.End, Records: append([]TimedDigest{}, records[chunk*RecordsPerEvidence:end]...)})
			if err != nil {
				return ProposedSource{}, err
			}
			refs = append(refs, reference(proof))
			entries = append(entries, proof)
		}
		rolling, err := RollingHash(records)
		if err != nil {
			return ProposedSource{}, err
		}
		group := Group{Group: name, Count: uint64(len(records)), RollingSHA256: rolling, Evidence: refs}
		if len(records) > 0 {
			first, last := records[0].At, records[len(records)-1].At
			group.First, group.Last = &first, &last
		}
		sidecar.Groups[name] = group
	}
	for _, owner := range []string{"A", "B", "C", "D"} {
		sidecar.Owners[owner] = Owner{Owner: owner, Status: "incomplete", Reason: "evidence_missing", Evidence: []EvidenceRef{}}
	}
	// A claims no more than its actual canonical redaction/exclusion/9-group
	// snapshot verification; raw owner payloads and other-owner flags stay out.
	summary, err := OwnerASummary(sidecar)
	if err != nil {
		return ProposedSource{}, err
	}
	ownerProof, err := registered(expected.Scope, OwnerProof{Version: "system-backup-control-owner-proof.v1", Scope: expected.Scope, Owner: "A", SummarySHA256: summary})
	if err != nil {
		return ProposedSource{}, err
	}
	entries = append(entries, ownerProof)
	sidecar.Owners["A"] = Owner{Owner: "A", Status: "complete", Reason: "none", Summary: &summary, Evidence: []EvidenceRef{reference(ownerProof)}}
	sort.Slice(entries, func(i, j int) bool { return entries[i].PublicID < entries[j].PublicID })
	sidecarRaw, err := Canonical(sidecar)
	if err != nil {
		return ProposedSource{}, err
	}
	proofsRaw, err := CanonicalProofs(ProofBundle{Version: "system-backup-control-evidence-proofs.v1", Scope: expected.Scope, Entries: entries})
	if err != nil {
		return ProposedSource{}, err
	}
	if _, err = Verify(ctx, sidecarRaw, proofsRaw, expected); err != nil {
		return ProposedSource{}, err
	}
	locator := sourceLocator(expected, sidecar, entries, SHA256(sidecarRaw), SHA256(proofsRaw))
	if locator.Validate() != nil {
		return ProposedSource{}, ErrInvalid
	}
	return ProposedSource{Prepared: PreparedSource{Scope: expected.Scope, SidecarJSON: sidecarRaw, SidecarSHA256: SHA256(sidecarRaw), ProofsJSON: proofsRaw, ProofsSHA256: SHA256(proofsRaw), Locator: locator}, Evidence: entries}, nil
}

func OwnerASummary(s Sidecar) (string, error) {
	raw, err := Canonical(struct {
		Scope     Scope
		Exclusion Exclusion
		Redaction Redaction
		Groups    map[string]Group
	}{s.Scope, s.Exclusion, s.Redaction, s.Groups})
	if err != nil {
		return "", err
	}
	return SHA256(raw), nil
}
