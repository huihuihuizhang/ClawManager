package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
)

func TestOriginalArchiveRenewalDirectory(t *testing.T) {
	base := filepath.Join(t.TempDir(), "archive-evidence-recovery")
	first := strings.Repeat("1", 64)
	second := strings.Repeat("2", 64)
	legacy := base + "-renewal"
	long := base
	for len(filepath.Base(long+"-renewal")) <= 255 {
		long += "-renewal"
	}
	compact := base + "-renewal-" + first
	for _, tc := range []struct {
		name, previous, digest, want string
	}{
		{"first legacy", base, first, legacy},
		{"existing legacy", legacy, first, legacy + "-renewal"},
		{"component limit", long, first, compact},
		{"compact successor", compact, second, base + "-renewal-" + second},
		{"wrong anchor", filepath.Join(filepath.Dir(base), "other-archive-recovery"), first, ""},
		{"unexpected suffix", base + "-alternate", first, ""},
		{"unqualified digest", base, "invalid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := originalArchiveRenewalDirectory(base, tc.previous, tc.digest)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("directory = %q, %t; want %q", got, ok, tc.want)
			}
		})
	}
}

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
