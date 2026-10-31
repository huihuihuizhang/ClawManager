package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Synthetic deterministic protocol data only; live original SQL capture and
// C encryption permission are tested by the actual service/worker owners.
func protocolSnapshot(t *testing.T, count int) Snapshot {
	t.Helper()
	end := time.Date(2026, 10, 31, 1, 2, 3, 0, time.UTC)
	scope := Scope{Installation: "installation_control_fixture", Backup: "sbk_00000000-0000-4000-8000-000000000001", Attempt: 3}
	expected := Expected{Scope: scope, ConfigSHA256: SHA256([]byte("original config")), SourceIdentitySHA256: SHA256([]byte("original source")), SchemaRegistry: RegistryPin{Version: "schema-r1", SHA256: SHA256([]byte("schema registry"))}, RedactionRegistry: RegistryPin{Version: "redaction-r1", SHA256: SHA256([]byte("redaction registry"))}}
	names := []string{"system_backup_v2_backups", "system_backup_v2_evidence"}
	namesSHA, err := namesHash(names)
	if err != nil {
		t.Fatal(err)
	}
	source, err := registered(scope, SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: scope, ConfigSHA256: expected.ConfigSHA256, SourceIdentitySHA256: expected.SourceIdentitySHA256, Registry: expected.SchemaRegistry, ExcludedNamesSHA256: namesSHA, IncludedControlCount: 0})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Expected: expected, Start: end.Add(-time.Minute), End: end, Generated: end, ExcludedControlObjects: names, SourceExclusion: source, Groups: map[string][]TimedDigest{}}
	for _, name := range GroupNames() {
		snapshot.Groups[name] = []TimedDigest{}
	}
	for i := 0; i < count; i++ {
		snapshot.Groups["event"] = append(snapshot.Groups["event"], TimedDigest{At: snapshot.Start.Add(time.Duration(i+1) * time.Millisecond), SHA256: SHA256([]byte(fmt.Sprintf("canonical redacted actual event %d", i)))})
	}
	return snapshot
}

func TestControlEvidenceCompleteWindowChunksAndLocatorOnlySerialization(t *testing.T) {
	snapshot := protocolSnapshot(t, 121)
	proposal, err := Assemble(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := Verify(context.Background(), proposal.Prepared.SidecarJSON, proposal.Prepared.ProofsJSON, snapshot.Expected)
	if err != nil || sidecar.Groups["event"].Count != 121 || len(sidecar.Groups["event"].Evidence) != 4 || sidecar.Owners["A"].Status != "complete" || sidecar.Owners["B"].Status != "incomplete" {
		t.Fatal("complete declared window not preserved", err)
	}
	for _, entry := range proposal.Evidence {
		if len(entry.Payload) > 8192 {
			t.Fatal("registered inline evidence exceeded original DDL bound")
		}
	}
	rebuilt, err := Rebuild(context.Background(), proposal.Prepared.Locator, proposal.Evidence)
	if err != nil || !bytes.Equal(rebuilt.SidecarJSON, proposal.Prepared.SidecarJSON) || !bytes.Equal(rebuilt.ProofsJSON, proposal.Prepared.ProofsJSON) {
		t.Fatal("immutable locator failed deterministic rebuild", err)
	}
	raw, err := json.Marshal(proposal.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{[]byte(`"record_groups"`), []byte(`"recorded_at"`), []byte(`"canonical_redacted_record_sha256"`), []byte(`"payload"`)} {
		if bytes.Contains(raw, plain) {
			t.Fatal("plaintext evidence entered a serializable Job/ConfigMap source")
		}
	}
	if err = ValidatePrepared(context.Background(), rebuilt, snapshot.Expected); err != nil {
		t.Fatal("historical intrinsic proof depended on today's clock", err)
	}
}

func TestControlEvidenceRejectsMissingProofRedactionOwnerAndChunkForgery(t *testing.T) {
	snapshot := protocolSnapshot(t, 81)
	proposal, err := Assemble(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing-body", "redaction-not-applied", "owner-forgery", "group-count", "chunk-order", "extra-secret", "wrong-source", "wrong-config"} {
		t.Run(mode, func(t *testing.T) {
			var sidecar Sidecar
			var proofs ProofBundle
			if closed(proposal.Prepared.SidecarJSON, &sidecar) != nil || closedLimit(proposal.Prepared.ProofsJSON, &proofs, MaxProofBytes) != nil {
				t.Fatal("protocol fixture")
			}
			expected := snapshot.Expected
			switch mode {
			case "missing-body":
				proofs.Entries = proofs.Entries[1:]
			case "redaction-not-applied":
				sidecar.Redaction.Applied = false
			case "owner-forgery":
				owner := sidecar.Owners["B"]
				owner.Status = "complete"
				owner.Reason = "none"
				hash := SHA256([]byte("unproven owner"))
				owner.Summary = &hash
				owner.Evidence = sidecar.Owners["A"].Evidence
				sidecar.Owners["B"] = owner
			case "group-count":
				group := sidecar.Groups["event"]
				group.Count--
				sidecar.Groups["event"] = group
			case "chunk-order":
				group := sidecar.Groups["event"]
				group.Evidence[0], group.Evidence[1] = group.Evidence[1], group.Evidence[0]
				sidecar.Groups["event"] = group
			case "extra-secret":
				var fields map[string]any
				json.Unmarshal(proposal.Prepared.SidecarJSON, &fields)
				fields["token"] = "must-never-be-persisted"
				raw, _ := Canonical(fields)
				if _, err := Verify(context.Background(), raw, proposal.Prepared.ProofsJSON, expected); err == nil {
					t.Fatal("unredacted extra body accepted")
				}
				return
			case "wrong-source":
				expected.SourceIdentitySHA256 = SHA256([]byte("another actual source"))
			case "wrong-config":
				expected.ConfigSHA256 = SHA256([]byte("another config"))
			}
			sidecarRaw, _ := Canonical(sidecar)
			proofRaw, _ := CanonicalProofs(proofs)
			if _, err := Verify(context.Background(), sidecarRaw, proofRaw, expected); err == nil {
				t.Fatal("forged/incomplete proof accepted")
			}
		})
	}
}

func TestControlEvidenceCapacityDoesNotTruncateOrShortenWindow(t *testing.T) {
	snapshot := protocolSnapshot(t, MaxGroupRecords+1)
	start, end := snapshot.Start, snapshot.End
	proposal, err := Assemble(context.Background(), snapshot)
	if !errors.Is(err, ErrCapacity) || proposal.Prepared.SidecarJSON != nil || proposal.Prepared.ProofsJSON != nil || len(proposal.Evidence) != 0 || !snapshot.Start.Equal(start) || !snapshot.End.Equal(end) {
		t.Fatal("over-budget original window was silently changed", err)
	}
}
