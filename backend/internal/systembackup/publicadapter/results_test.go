package publicadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

func TestWorkerReceiptConversionPreservesRealBindingAndHashes(t *testing.T) {
	f, _, plan := setup(t)
	result := worker.Result{Receipt: staging.Receipt{Name: "users.enc", Size: 1024, SHA256: strings.Repeat("e", 64)}, Files: 2, Bytes: 500}
	seal := SealedPart{Reference: "immutable-object-version", ContentSHA256: result.Receipt.SHA256, EvidenceIDs: []string{"sev_seal"}}
	out, err := BuildPartResult(f.in, plan, "users", f.binding, result, seal)
	if err != nil {
		t.Fatal(err)
	}
	var cp Checkpoint
	if json.Unmarshal(out.Checkpoint, &cp) != nil || cp.InvocationSHA256 != f.x.Parts[0].InvocationSHA256 || cp.ContentSHA256 != result.Receipt.SHA256 || cp.JobUID != f.binding.UID || cp.InstallationID != f.in.Authority.InstallationID || out.Statistics["sealed_bytes"] != 1024 || out.Statistics["bytes"] != 500 {
		t.Fatal(out, cp)
	}
	seal.ContentSHA256 = strings.Repeat("f", 64)
	if _, err := BuildPartResult(f.in, plan, "users", f.binding, result, seal); err == nil {
		t.Fatal("changed ciphertext reused old receipt checksum")
	}
	seal.ContentSHA256 = result.Receipt.SHA256
	result.Verified = true
	if _, err := BuildPartResult(f.in, plan, "users", f.binding, result, seal); err == nil {
		t.Fatal("restore result accepted as capture")
	}
}

func TestFormalReceiptConversionConsumesOnlyOriginalFormalPlan(t *testing.T) {
	f, runner, _ := setup(t)
	var i worker.Invocation
	if json.Unmarshal(f.x.Parts[0].InvocationJSON, &i) != nil {
		t.Fatal("fixture invocation")
	}
	i.FormalCapture = &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: "original-envelope.json", MaxFrames: 8}
	i.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://kms.fixture.invalid", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("b", 64), RegistryVersion: "original-r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: f.in.Authority.InstallationID, BackupPublicID: f.in.Authority.TaskPublicID, AttemptNo: i.Request.Binding.Attempt, Phase: "capture", Part: i.Request.Binding.Path, PartIndex: "0", EnvelopeID: i.Request.Binding.EnvelopeID, CaptureContextHash: i.Request.Binding.CaptureContextHash}}}
	raw, _ := json.Marshal(i)
	f.x.Parts[0].InvocationJSON = raw
	f.x.Parts[0].InvocationSHA256 = digest(raw)
	plan, err := runner.Prepare(context.Background(), f.in, f)
	if err != nil {
		t.Fatal(err)
	}
	candidate := worker.FormalCaptureResult{Version: "public-c-stream-candidate.v1alpha1", InvocationSHA256: digest(raw), Ciphertext: staging.Receipt{Name: i.Request.ArtifactName, Size: 1024, SHA256: strings.Repeat("c", 64)}, Envelope: staging.Receipt{Name: i.FormalCapture.EnvelopeName, Size: 500, SHA256: strings.Repeat("d", 64)}, Files: 2, Bytes: 500}
	seal := SealedPart{Reference: "controller-formal-seal.v1/original-cipher/original-envelope", ContentSHA256: candidate.Ciphertext.SHA256, EvidenceIDs: []string{}}
	out, err := BuildFormalPartResult(f.in, plan, "users", f.binding, candidate, seal)
	if err != nil || out.Statistics["sealed_bytes"] != 1024 || out.Statistics["files"] != 2 {
		t.Fatal("formal result conversion failed", err)
	}
	legacy := worker.Result{Receipt: candidate.Ciphertext, Files: 2, Bytes: 500}
	if _, err = BuildPartResult(f.in, plan, "users", f.binding, legacy, seal); err == nil {
		t.Fatal("formal plan borrowed legacy result path")
	}
	candidate.InvocationSHA256 = strings.Repeat("e", 64)
	if _, err = BuildFormalPartResult(f.in, plan, "users", f.binding, candidate, seal); err == nil {
		t.Fatal("foreign candidate converted")
	}
}
