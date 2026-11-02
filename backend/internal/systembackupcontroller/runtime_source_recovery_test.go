package systembackupcontroller

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Serialization tests grant no physical recovery or SQL authority. Actual
// producer/StageTx and transaction failure cases require the separate integration
// run; these tests protect immutable set/identity/byte binding only.
func sourceRecoverySerializationFixture(t *testing.T) *PreparedSourceRecovery {
	t.Helper()
	scope := ce.Scope{Installation: "installation", Backup: "sbk_original", Attempt: 2}
	writers := []b.FrozenWriter{
		{ID: "registered-b", Original: flow.State{UID: "scope/registered-b", Generation: 3, Checkpoint: "original-b"}},
		{ID: "registered-a", Original: flow.State{UID: "scope/registered-a", Generation: 3, Checkpoint: "original-a"}},
	}
	p := &PreparedSourceRecovery{desc: b.Discovery{Writers: writers}, root: sourceRecoveryRoot{Version: "original-source-recovery.v1", Scope: scope, ConfigVersion: 3, ConfigSHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64), SourceSHA256: strings.Repeat("c", 64), RegistrySHA256: strings.Repeat("d", 64), Epoch: 7, WriterCount: 2, ObservedAt: time.Date(2026, 11, 2, 0, 0, 0, 123456000, time.UTC)}}
	p.root.CaptureResultSHA256, p.root.FrozenControlSHA256 = strings.Repeat("e", 64), strings.Repeat("f", 64)
	refs := []ce.EvidenceRef{}
	for _, writer := range sourceRecoverySorted(writers) {
		ob := SourceRecoveryObservation{WriterID: writer.ID, OriginalSHA256: sourceRecoveryOriginalSHA(writer), Scope: "registered_application_mutation_lease_boundary", Facts: json.RawMessage(`{"Version":"source-recovery-lease-observation.v1","ApplicationScope":"scope"}`)}
		ob.Facts, _ = ce.Canonical(ob.Facts)
		ob.References = []SourceRecoverySQLReference{{Kind: "lease_epoch", Identity: writer.ID, SHA256: recordHash(ob.Facts)}}
		entry, err := sourceRecoveryEntry(scope, writer.ID, sourceRecoveryLeaf{Version: "original-source-recovery-writer.v1", Scope: scope, ConfigSHA256: p.root.ConfigSHA256, SourceSHA256: p.root.SourceSHA256, RegistrySHA256: p.root.RegistrySHA256, CaptureResultSHA256: p.root.CaptureResultSHA256, FrozenControlSHA256: p.root.FrozenControlSHA256, Epoch: p.root.Epoch, SourceRecoveryObservation: ob})
		if err != nil {
			t.Fatal(err)
		}
		p.entries = append(p.entries, entry)
		refs = append(refs, ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256})
	}
	raw, _ := json.Marshal(refs)
	p.root.WritersSHA256 = recordHash(raw)
	root, err := sourceRecoveryEntry(scope, "", p.root)
	if err != nil {
		t.Fatal(err)
	}
	p.entries = append([]ce.RegisteredEvidence{root}, p.entries...)
	return p
}

func TestSourceRecoverySerializationBindsOriginalCompleteSet(t *testing.T) {
	p := sourceRecoverySerializationFixture(t)
	if err := p.validateEntries(); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(p.desc.Writers)
	_ = sourceRecoverySorted(p.desc.Writers)
	after, _ := json.Marshal(p.desc.Writers)
	if !bytes.Equal(before, after) {
		t.Fatal("sorting mutated original encrypted-plan writer order")
	}
	var root sourceRecoveryRoot
	if json.Unmarshal(p.entries[0].Payload, &root) != nil || !root.ObservedAt.Equal(p.root.ObservedAt) {
		t.Fatal("original SQL microsecond timestamp changed")
	}
	var leaf sourceRecoveryLeaf
	if json.Unmarshal(p.entries[1].Payload, &leaf) != nil || leaf.Scope != p.root.Scope || leaf.SourceRecoveryObservation.Scope != "registered_application_mutation_lease_boundary" {
		t.Fatal("record scope and observation scope did not survive serialization")
	}
}

func TestSourceRecoverySerializationRefusesMissingExtraOrChangedOriginal(t *testing.T) {
	for _, name := range []string{"missing", "extra", "reordered", "checkpoint", "source", "registry", "result", "frozen-control", "epoch", "timestamp", "leaf-bytes"} {
		t.Run(name, func(t *testing.T) {
			p := sourceRecoverySerializationFixture(t)
			switch name {
			case "missing":
				p.entries = p.entries[:len(p.entries)-1]
			case "extra":
				p.entries = append(p.entries, p.entries[1])
			case "reordered":
				p.entries[1], p.entries[2] = p.entries[2], p.entries[1]
			case "checkpoint":
				p.desc.Writers[0].Original.Checkpoint = "different-original"
			case "source":
				p.root.SourceSHA256 = strings.Repeat("e", 64)
			case "registry":
				p.root.RegistrySHA256 = strings.Repeat("e", 64)
			case "result":
				p.root.CaptureResultSHA256 = strings.Repeat("a", 64)
			case "frozen-control":
				p.root.FrozenControlSHA256 = strings.Repeat("a", 64)
			case "epoch":
				p.root.Epoch++
			case "timestamp":
				p.root.ObservedAt = p.root.ObservedAt.Add(time.Microsecond)
			case "leaf-bytes":
				p.entries[1].Payload = append(p.entries[1].Payload, ' ')
			}
			if p.validateEntries() == nil {
				t.Fatal("changed original binding accepted")
			}
		})
	}
}

func TestSourceRecoveryStableIDSeparatesAttemptsAndWriterFromRoot(t *testing.T) {
	scope := ce.Scope{Installation: "installation", Backup: "sbk_original", Attempt: 1}
	id := sourceRecoveryID(scope, "writer")
	if id != sourceRecoveryID(scope, "writer") || id == sourceRecoveryID(scope, "") {
		t.Fatal("unstable or root-colliding ID")
	}
	scope.Attempt++
	if id == sourceRecoveryID(scope, "writer") {
		t.Fatal("attempts shared immutable carrier ID")
	}
}

func TestSourceRecoveryRecordBoundedAndRejectsEmptyPhysicalClaims(t *testing.T) {
	if _, err := sourceRecoveryEntry(ce.Scope{}, "writer", map[string]string{"body": strings.Repeat("x", 8192)}); err == nil {
		t.Fatal("unbounded inline record")
	}
	base := SourceRecoveryObservation{WriterID: "writer", OriginalSHA256: strings.Repeat("a", 64), Scope: "native_instance_pid_namespace_and_mount_lifecycle_with_kubernetes_volume_bindings"}
	for _, facts := range []string{`{}`, `null`, `{"Version":"source-recovery-physical-observation.v1","Kind":"gateway","Recovered":[]}`, `{"Version":"source-recovery-physical-observation.v1","Kind":"gateway","Runtime":null,"Recovered":[{}]}`} {
		base.Facts = json.RawMessage(facts)
		if validSourceRecoveryObservation(base) {
			t.Fatal("empty/default physical success claim accepted")
		}
	}
}
