package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Explicit protocol fixture; it does not claim SQL registration or a live grant.
func controlContentProposal(t *testing.T, original ...ce.Expected) ce.ProposedSource {
	t.Helper()
	end := time.Date(2026, 10, 31, 1, 2, 3, 0, time.UTC)
	scope := ce.Scope{Installation: "installation_control_content", Backup: "sbk_00000000-0000-4000-8000-000000000001", Attempt: 3}
	expected := ce.Expected{Scope: scope, ConfigSHA256: hash([]byte("config")), SourceIdentitySHA256: hash([]byte("source")), SchemaRegistry: ce.RegistryPin{Version: "s1", SHA256: hash([]byte("schema"))}, RedactionRegistry: ce.RegistryPin{Version: "r1", SHA256: hash([]byte("redaction"))}}
	if len(original) == 1 {
		expected = original[0]
		scope = expected.Scope
	}
	names := []string{"system_backup_v2_evidence"}
	namesRaw, _ := ce.Canonical(names)
	payload, err := ce.Canonical(ce.SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: scope, ConfigSHA256: expected.ConfigSHA256, SourceIdentitySHA256: expected.SourceIdentitySHA256, Registry: expected.SchemaRegistry, ExcludedNamesSHA256: hash(namesRaw)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ce.Snapshot{Expected: expected, Start: end.Add(-time.Minute), End: end, Generated: end, ExcludedControlObjects: names, SourceExclusion: ce.RegisteredEvidence{PublicID: "sev_original_source_fixture", SHA256: hash(payload), OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: payload}, Groups: map[string][]ce.TimedDigest{}}
	for _, name := range ce.GroupNames() {
		snapshot.Groups[name] = []ce.TimedDigest{}
	}
	snapshot.Groups["event"] = []ce.TimedDigest{{At: end.Add(-time.Second), SHA256: hash([]byte("nonempty redacted event"))}}
	proposal, err := ce.Assemble(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestControlEvidenceIndependentContentRejectsValidHashMalformedProofs(t *testing.T) {
	proposal := controlContentProposal(t)
	for _, part := range []string{ce.Part, ce.ProofPart} {
		payload := proposal.Prepared.SidecarJSON
		if part == ce.ProofPart {
			payload = proposal.Prepared.ProofsJSON
		}
		if err := inspectControlEvidencePart(context.Background(), bytes.NewReader(payload), part, proposal.Prepared.Locator); err != nil {
			t.Fatal(part, err)
		}
	}
	for _, fault := range []string{"missing-body", "forged-body", "wrong-scope", "suffix", "unknown-field", "sidecar-cutoff", "sidecar-registry"} {
		t.Run(fault, func(t *testing.T) {
			locator := proposal.Prepared.Locator
			part := ce.ProofPart
			var bundle ce.ProofBundle
			json.Unmarshal(proposal.Prepared.ProofsJSON, &bundle)
			switch fault {
			case "missing-body":
				bundle.Entries = bundle.Entries[1:]
			case "forged-body":
				bundle.Entries[0].Payload = json.RawMessage(`{}`)
			case "wrong-scope":
				bundle.Backup = "sbk_foreign"
			}
			raw, _ := ce.CanonicalProofs(bundle)
			if fault == "suffix" {
				raw = append(raw, []byte(`{}`)...)
			}
			if fault == "unknown-field" {
				raw = append([]byte(`{"unknown":1,`), raw[1:]...)
			}
			if fault == "sidecar-cutoff" || fault == "sidecar-registry" {
				var sidecar ce.Sidecar
				json.Unmarshal(proposal.Prepared.SidecarJSON, &sidecar)
				if fault == "sidecar-cutoff" {
					sidecar.End = sidecar.End.Add(time.Second)
				} else {
					sidecar.Exclusion.SHA256 = hash([]byte("foreign registry"))
				}
				raw, _ = ce.Canonical(sidecar)
				part = ce.Part
				locator.SidecarSHA256 = hash(raw)
			} else {
				locator.ProofsSHA256 = hash(raw)
			}
			// Even a matching frozen payload checksum is insufficient.
			if err := inspectControlEvidencePart(context.Background(), bytes.NewReader(raw), part, locator); err == nil {
				t.Fatal("malformed content accepted")
			}
		})
	}
}
