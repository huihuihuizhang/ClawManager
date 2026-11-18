package install

import (
	"os"
	"path/filepath"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
)

func TestRecoverOriginalArchiveIntentPreservesBaseline(t *testing.T) {
	dir := filepath.Clean(t.TempDir())
	prior := originalArchiveEvidenceIntent{
		Version: "original-archive-evidence-material-intent.v1", Plan: "plan", Enrollment: "enrollment",
		Source: OriginalArchiveEvidenceMaterialOptions{OutputDirectory: dir, UnwrapPodName: "controller"},
		Role:   a.VaultPermissionRole{AuthMount: "jwt", Role: "read", Policy: "read", PodUID: "pod"},
	}
	const key = "/v1/transit/keys/c1"
	const role = "/v1/auth/jwt/role/read"
	const policy = "/v1/sys/policies/acl/read"
	intent, err := canonical(prior)
	if err != nil {
		t.Fatal(err)
	}
	before, err := canonical(map[string]string{key: "original"})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"archive-evidence.intent.json": intent, "archive-native.sent.json": intent,
		"archive-provider-metadata.before.json": before,
	} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	recovery := OriginalArchiveEvidenceRecovery{
		Intent:         BootstrapSourceFilePin{File: filepath.Join(dir, "archive-evidence.intent.json"), SHA256: hash(intent)},
		BeforeMetadata: BootstrapSourceFilePin{File: filepath.Join(dir, "archive-provider-metadata.before.json"), SHA256: hash(before)},
	}
	expected := prior
	expected.Source.OutputDirectory += "-recovery"
	current := map[string]string{key: "original", role: "retained", policy: "retained"}
	if _, _, err = recoverOriginalArchiveIntent(recovery, expected, current); err != nil {
		t.Fatal(err)
	}
	current[key] = "changed"
	if _, _, err = recoverOriginalArchiveIntent(recovery, expected, current); err == nil {
		t.Fatal("accepted changed key metadata")
	}
	current[key] = "original"
	expected.Role.PodUID = "different"
	if _, _, err = recoverOriginalArchiveIntent(recovery, expected, current); err == nil {
		t.Fatal("accepted a different controller")
	}
	expected.Role.PodUID = prior.Role.PodUID
	if err = os.WriteFile(filepath.Join(dir, "archive-evidence-unwrap.jwt"), []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = recoverOriginalArchiveIntent(recovery, expected, current); err == nil {
		t.Fatal("accepted an already issued credential")
	}
}
