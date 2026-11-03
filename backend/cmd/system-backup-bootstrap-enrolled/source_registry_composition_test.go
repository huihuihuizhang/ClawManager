package main

import (
	"path/filepath"
	"strings"
	"testing"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

func TestEnrolledSourceRegistriesPreserveOriginalOwnerAndBinding(t *testing.T) {
	dir := t.TempDir()
	capture := install.NewCaptureSigningConsumer(filepath.Join(dir, "capture.json"), filepath.Join(dir, "capture.sha256"))
	files := install.BootstrapSourceRegistryFiles{RecordFile: filepath.Join(dir, "registries.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(dir, "registries.sig")}
	native := execution.BootstrapSourceNativeRegistryFiles{RedisSources: install.BootstrapSourceFilePin{File: filepath.Join(dir, "redis.json"), SHA256: strings.Repeat("b", 64)}, SecretAllowlist: install.BootstrapSourceFilePin{File: filepath.Join(dir, "secret-policy.json"), SHA256: strings.Repeat("c", 64)}}
	base := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{"classification": capture}, References: map[string]sec.BootstrapResourceValidator{"capture_signing": capture}, CrossResources: capture}
	linked, resource, err := addOriginalSourceRegistryTerminal(base, capture, files, native)
	if err != nil || !originalSourceRegistryAliases(linked, resource) {
		t.Fatal("original source registry owner not linked", err)
	}
	if len(base.Registries) != 1 || linked.Registries["classification"] != capture || linked.References["capture_signing"] != capture || linked.CrossResources != capture {
		t.Fatal("linking changed original owners or mutated caller map")
	}
	compositionSHA, err := resource.BindingSHA256()
	expected, expectedErr := execution.NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, native)
	if expectedErr != nil {
		t.Fatal(expectedErr)
	}
	expectedSHA, expectedErr := expected.BindingSHA256()
	if err != nil || expectedErr != nil || compositionSHA != expectedSHA || compositionSHA == files.RecordSHA256 {
		t.Fatal("composition binding replaced by record content hash", err, expectedErr)
	}
	for _, key := range []string{"parts", "redis_sources", "secret_allowlist", "source_writers"} {
		collision := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{key: capture}}
		if _, r, err := addOriginalSourceRegistryTerminal(collision, capture, files, native); err == nil || r != nil {
			t.Fatal("existing registry owner overwritten", key)
		}
		collision.Registries[key] = nil
		if _, r, err := addOriginalSourceRegistryTerminal(collision, capture, files, native); err == nil || r != nil {
			t.Fatal("declared nil registry slot overwritten", key)
		}
	}
	if _, r, err := addOriginalSourceRegistryTerminal(sec.BootstrapOwnerAdapters{Candidates: &sec.BootstrapDeploymentCandidates{}}, capture, files, native); err == nil || r != nil {
		t.Fatal("candidate authority silently replaced")
	}
	linked.Registries["parts"] = capture
	if originalSourceRegistryAliases(linked, resource) {
		t.Fatal("later owner replacement concealed")
	}
}
