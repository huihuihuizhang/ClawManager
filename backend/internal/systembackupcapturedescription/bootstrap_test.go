package systembackupcapturedescription

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	w "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// DATA only. The external checkpoint pins are explicit fixtures; no actual
// certificate signature, native version readback or key authority is claimed.
func bootstrapFixture(t *testing.T) (Bootstrap, map[string]string) {
	t.Helper()
	scope := Scope{InstallationID: "installation_fixture", TaskPublicID: "sbk_fixture", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), AttemptNo: 2, CaptureContextSHA256: strings.Repeat("b", 64)}
	b := Bootstrap{Version: BootstrapVersion, Scope: scope, SourceInventorySHA256: strings.Repeat("c", 64), Members: []AdministrativeMember{}}
	pins := map[string]string{"business_sql": strings.Repeat("f", 64)}
	limit, _ := Budget(1)
	parts := []struct {
		part, op, path, cipher, envelope string
		limit                            int64
	}{{Part, Operation, LogicalCipherName, CipherPath, EnvelopePath, limit}, {ControlPart, ControlOperation, "control-evidence.enc", "control/evidence.json.enc", "control/evidence.envelope.json", 262144}, {ProofPart, ControlOperation, "control-evidence-proofs.enc", "control/evidence-proofs.json.enc", "control/evidence-proofs.envelope.json", 8 << 20}}
	for i, p := range parts {
		cp := checkpoint{InstallationID: scope.InstallationID, ConfigVersion: 1, SchemaVersion: "system-backup-b-checkpoint.v1", TaskPublicID: scope.TaskPublicID, AttemptNo: 2, Phase: "capture", ConfigSHA256: scope.ConfigSHA256, InventorySHA256: b.SourceInventorySHA256, Part: p.part, JobUID: "job-" + p.part, JobGeneration: 1, InvocationSHA256: strings.Repeat("d", 64), SealedRef: "original-sealed-reference", ContentSHA256: strings.Repeat("e", 64)}
		raw, _ := json.Marshal(cp)
		canonical, err := jsoncanonicalizer.Transform(raw)
		if err != nil {
			t.Fatal(err)
		}
		pins[p.part] = SHA256(canonical)
		b.Members = append(b.Members, AdministrativeMember{Selection: Selection{Part: p.part, Operation: p.op, PartIndex: uint32(i)}, CipherPath: p.cipher, EnvelopePath: p.envelope, CipherBytes: 128, CipherSHA256: cp.ContentSHA256, EnvelopeBytes: 16, EnvelopeSHA256: strings.Repeat("f", 64), Stream: w.StreamSpec{Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: scope.InstallationID, BackupPublicID: scope.TaskPublicID, AttemptNo: "2", Phase: "capture", Part: p.part, PartIndex: string(rune('0' + i)), EnvelopeID: "original-envelope-" + p.part, CaptureContextHash: scope.CaptureContextSHA256}}, Path: p.path, MaxPlaintextBytes: p.limit, MaxFrames: 64}, CheckpointJSON: raw})
	}
	return b, pins
}

func TestDescriptionBootstrapUsesExternalCertificateCheckpointPins(t *testing.T) {
	b, pins := bootstrapFixture(t)
	raw, err := EncodeBootstrap(b, pins)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBootstrap(raw, b.Scope, b.SourceInventorySHA256, pins)
	if err != nil || len(decoded.Members) != 3 || !bytes.Equal(decoded.Members[0].CheckpointJSON, b.Members[0].CheckpointJSON) {
		t.Fatal("bounded bootstrap", err)
	}
	for _, bad := range []string{"wrong-certificate", "scope", "inventory", "extra-member", "spec-context", "spec-limit", "checkpoint-reencoded", "unknown-field"} {
		t.Run(bad, func(t *testing.T) {
			actual, external := bootstrapFixture(t)
			data := bytes.Clone(raw)
			switch bad {
			case "wrong-certificate":
				external[Part] = strings.Repeat("a", 64)
			case "scope":
				actual.Scope.AttemptNo++
			case "inventory":
				actual.SourceInventorySHA256 = strings.Repeat("a", 64)
			case "extra-member":
				actual.Members = append(actual.Members, actual.Members[0])
			case "spec-context":
				actual.Members[0].Stream.Request.Context.Part = ControlPart
			case "spec-limit":
				actual.Members[0].Stream.MaxPlaintextBytes++
			case "checkpoint-reencoded":
				actual.Members[0].CheckpointJSON = append(actual.Members[0].CheckpointJSON, ' ')
			case "unknown-field":
				data = append([]byte(`{"unknown":true,`), data[1:]...)
			}
			if bad != "unknown-field" {
				data, _ = json.Marshal(actual)
				data, _ = jsoncanonicalizer.Transform(data)
			}
			if _, err := DecodeBootstrap(data, b.Scope, b.SourceInventorySHA256, external); err == nil {
				t.Fatal("unbound bootstrap accepted")
			}
		})
	}
}
