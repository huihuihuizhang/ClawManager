package publicadapter

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
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
